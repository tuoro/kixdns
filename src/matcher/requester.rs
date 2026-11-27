//! 谁在问：规则能分辨的请求方（地址、MAC、带不带 EDNS、客户端自己的 ECS），规则区分它们的依据（`RequesterTest`），
//! 一个 pipeline 连同它跳得到的 pipeline 合起来的依据（`RequesterScope`），以及缓存和 inflight 键里请求方那一部分
//! (`RequesterKey`)
//! Who is asking: the requester as far as rules can tell (address, MAC, EDNS or not, the
//! client's own ECS), what rules tell requesters apart by (`RequesterTest`), what a pipeline
//! with those it can jump to tells them apart by (`RequesterScope`), and the requester's part of
//! the cache and inflight keys (`RequesterKey`)

use super::*;
/// Who is asking, as far as rules can tell.
/// 规则能分辨的请求方。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Requester {
    /// The client's address / 客户端地址
    pub address: IpAddr,
    /// The MAC the host's neighbor table gave for the address as the request came in, looked
    /// up only when the configuration writes client_mac (see `Engine::client_mac`): choosing
    /// the pipeline, the keys and the rules of one request all go by this one lookup
    /// 请求进来时本机邻居表给这个地址的 MAC，配置写了 client_mac 才查（见 `Engine::client_mac`）：一个请求选
    /// pipeline、算键、求值规则都按这一次查到的
    pub mac: Option<crate::neighbor::Mac>,
    /// Whether the query carries EDNS / 查询是否带 EDNS
    pub edns: bool,
    /// The ECS option the client carries itself / 客户端自己带的 ECS 选项
    pub ecs: Option<crate::ecs::EcsKey>,
}

impl Requester {
    /// What the response cache can tell about this requester as far as ECS goes
    /// 响应缓存在 ECS 方面能分辨的这个请求方
    pub fn ecs_view(&self) -> crate::ecs_scope::EcsView {
        crate::ecs_scope::EcsView {
            peer: self.address,
            client: self.ecs,
        }
    }
}

/// One way a pipeline's rules can tell requesters apart.
/// 管道的规则区分请求方的一种依据。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RequesterTest {
    /// `client_ip`: whether the address is in the network / 地址是否在该网段内
    InNet(IpNet),
    /// `client_mac`: whether the neighbor table maps the address to this MAC
    /// 邻居表里这个地址对应的是不是这个 MAC
    Mac(crate::neighbor::Mac),
    /// `geoip_private`: whether the address is private / 地址是否私有
    Private,
    /// `geoip_country`: whether the address's GeoIP country or tag is one of these
    /// 地址的 GeoIP 国家或标签是否在其中
    Country(Vec<Arc<str>>),
    /// `edns_present`, and `response_edns_present`, since an upstream answers with
    /// EDNS when it is asked with it: whether the query carries EDNS
    /// `edns_present`，以及 `response_edns_present`（上游被带着 EDNS 询问时才带着 EDNS
    /// 回答）：查询是否带 EDNS
    Edns,
    /// ECS derived from the client: the subnet sent at these prefixes, none for a
    /// private address / 取自客户端的 ECS：按这些前缀发送的子网，私有地址不发送
    Subnet { prefix_v4: u8, prefix_v6: u8 },
}

impl RequesterTest {
    fn hash_outcome<H: Hasher>(
        &self,
        requester: Requester,
        geoip: &geoip::GeoIpManager,
        hasher: &mut H,
    ) {
        match self {
            Self::InNet(net) => net.contains(&requester.address).hash(hasher),
            Self::Mac(mac) => (requester.mac == Some(*mac)).hash(hasher),
            Self::Private => geoip::is_private_ip(requester.address).hash(hasher),
            Self::Country(codes) => geoip.matches_any_tag(requester.address, codes).hash(hasher),
            Self::Edns => requester.edns.hash(hasher),
            Self::Subnet {
                prefix_v4,
                prefix_v6,
            } => {
                let mode = config::EcsMode::FromClientIp {
                    prefix_v4: *prefix_v4,
                    prefix_v6: *prefix_v6,
                };
                match crate::ecs::plan(Some(&mode), requester.address, requester.ecs.as_ref()) {
                    crate::ecs::EcsPlan::Set(subnet) => {
                        hasher.write_u8(1);
                        subnet.hash_into(hasher);
                    }
                    _ => hasher.write_u8(0),
                }
            }
        }
    }
}

/// How a pipeline's answer can depend on the requester: the tests its rules,
/// and the rules a request may run before it answers, tell requesters apart by.
/// Those rules treat two requesters alike when every test does, so the two can
/// share cache and inflight entries.
/// 管道的应答如何取决于请求方：它的规则、以及请求在应答之前可能运行的规则，用来区分
/// 请求方的各项依据。每项依据都一样对待两个请求方时，这些规则对它们也一样，二者可以
/// 共用缓存和 inflight 条目。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RequesterScope {
    tests: Vec<RequesterTest>,
}

impl RequesterScope {
    /// The tests, in a fixed order / 各项依据，顺序固定
    pub fn tests(&self) -> &[RequesterTest] {
        &self.tests
    }

    fn add(&mut self, test: RequesterTest) {
        if !self.tests.contains(&test) {
            self.tests.push(test);
        }
    }

    fn extend(&mut self, other: &Self) {
        for test in &other.tests {
            self.add(test.clone());
        }
    }

    /// The requester's part of a key: how each test judges `requester`, the GeoIP country by
    /// `geoip`, the request's own copy of the data (see [`GeoManagers`]). Empty for a scope
    /// without tests.
    /// 键里属于请求方的部分：每项依据对 `requester` 的判定，GeoIP 国家按 `geoip` 判断，也就是这个请求自己那一份数据
    /// （见 [`GeoManagers`]）。没有依据时为空。
    pub fn key(&self, requester: Requester, geoip: &geoip::GeoIpManager) -> RequesterKey {
        let judge = |subnets: bool| {
            let mut tests = self
                .tests
                .iter()
                .filter(|test| matches!(test, RequesterTest::Subnet { .. }) == subnets)
                .peekable();
            tests.peek()?;
            let mut hasher = rustc_hash::FxHasher::default();
            for test in tests {
                test.hash_outcome(requester, geoip, &mut hasher);
            }
            Some(hasher.finish())
        };
        RequesterKey {
            class: judge(false),
            subnets: judge(true),
        }
    }
}

/// The requester's part of a response cache, inflight or rule cache key. Empty
/// for a pipeline whose answer does not depend on the requester, so its keys
/// stay as they were.
/// 响应缓存、inflight 和规则缓存键里属于请求方的部分。应答与请求方无关的 pipeline
/// 这里为空，键保持原样。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RequesterKey {
    /// How the scope's tests other than the ECS subnets judge the requester
    /// 范围内 ECS 子网以外的各项依据对请求方的判定
    pub class: Option<u64>,
    /// The ECS subnets the forwards would send for the requester. Only the inflight
    /// key carries them: a cached answer is tagged with the subnets it applies to
    /// (see `CacheEntry::reach`), while requests can only wait on one another when
    /// they send the same.
    /// 转发会为这个请求方发送的 ECS 子网。只有 inflight 键带着它们：缓存的应答标着它适用的
    /// 子网（见 `CacheEntry::reach`），而请求只有发送相同的子网才能互相等待。
    pub subnets: Option<u64>,
}

impl RequesterKey {
    /// No requester facts / 不含请求方信息
    pub const NONE: Self = Self {
        class: None,
        subnets: None,
    };

    /// The part of the response cache and rule cache keys / 响应缓存键和规则缓存键里的部分
    pub fn hash_into<H: Hasher>(&self, hasher: &mut H) {
        if let Some(class) = self.class {
            hasher.write_u8(1);
            class.hash(hasher);
        }
    }

    /// The part of the inflight key: the above, the subnets, and the client's own
    /// ECS option, which a forward without `ecs` passes upstream
    /// inflight 键里的部分：上面那些、子网，以及客户端自己带的 ECS 选项（不写 `ecs` 的
    /// 转发会把它转给上游）
    pub fn hash_inflight_into<H: Hasher>(
        &self,
        client_ecs: Option<&crate::ecs::EcsKey>,
        hasher: &mut H,
    ) {
        // Kept apart from the slot key even when nothing below is written
        // 即使下面什么都不写，也与槽位键分开
        hasher.write_u8(b'I');
        self.hash_into(hasher);
        if let Some(subnets) = self.subnets {
            hasher.write_u8(3);
            subnets.hash(hasher);
        }
        if let Some(client_ecs) = client_ecs {
            hasher.write_u8(4);
            client_ecs.hash(hasher);
        }
    }
}

/// What a pipeline's rules tell requesters apart by, each part for one use
/// below / 一个 pipeline 的规则区分请求方的依据，按下面的用途分开
pub(super) struct RuleReads {
    /// Request matchers / 请求匹配器
    request_matchers: RequesterScope,
    /// Request and response matchers / 请求匹配器和响应匹配器
    matchers: RequesterScope,
    /// The ECS subnets taken from the client that its forwards send
    /// 转发发送的取自客户端的 ECS 子网
    forward_subnets: RequesterScope,
    /// Those of them that the forwards among its answer actions send
    /// 其中回答动作里的转发发送的
    answer_subnets: RequesterScope,
    /// Pipelines its answer checks jump to / 回答检查跳到的 pipeline
    response_jumps: Vec<Arc<str>>,
    /// Pipelines its rules jump to after an earlier rule's answer check may have continued
    /// 前面的规则的回答检查可能 continue 之后，规则跳到的 pipeline
    continued_jumps: Vec<Arc<str>>,
    /// Pipelines its rules or answer checks jump to / 规则或回答检查跳到的 pipeline
    jumps: Vec<Arc<str>>,
    /// The Geo data its rules read / 规则读的 Geo 数据
    geo: GeoData,
}

impl RuleReads {
    pub(super) fn of(rules: &[RuntimeRule]) -> Self {
        let mut reads = Self {
            request_matchers: RequesterScope::default(),
            matchers: RequesterScope::default(),
            forward_subnets: RequesterScope::default(),
            answer_subnets: RequesterScope::default(),
            response_jumps: Vec::new(),
            continued_jumps: Vec::new(),
            jumps: Vec::new(),
            geo: GeoData::default(),
        };
        let mut answer_edns = false;
        // 按客户端地址发 ECS 的转发发送的子网
        // The subnet a forward sending ECS by the client's address sends
        let subnet = |action: &Action| match action {
            Action::Forward {
                ecs:
                    Some(config::EcsMode::FromClientIp {
                        prefix_v4,
                        prefix_v6,
                    }),
                ..
            } => Some(RequesterTest::Subnet {
                prefix_v4: *prefix_v4,
                prefix_v6: *prefix_v6,
            }),
            _ => None,
        };
        // 前面有没有哪条规则的回答检查会 continue / Whether an earlier rule's answer check continues
        let mut continued = false;
        for rule in rules {
            let (response_matchers, on_match, on_miss) =
                ResponsePhase::parts(rule.response_phase.as_deref());
            // 请求匹配器读的 GeoIP 只按客户端地址判断，不算（见 [`GeoData`]）/ The GeoIP request
            // matchers read judges the client address alone and does not count (see [`GeoData`])
            let request = rule
                .matchers
                .iter()
                .filter_map(|m| m.matcher.geo_tags())
                .filter(|tags| matches!(tags, GeoTags::Site(_)));
            let response = response_matchers
                .iter()
                .filter_map(|m| m.matcher.geo_tags());
            for tags in request.chain(response) {
                reads.geo.add(tags);
            }
            for m in rule.matchers.iter() {
                let test = match &m.matcher {
                    RuntimeMatcher::ClientIp { net } => RequesterTest::InNet(*net),
                    RuntimeMatcher::ClientMac { mac } => RequesterTest::Mac(*mac),
                    RuntimeMatcher::GeoipPrivate { .. } => RequesterTest::Private,
                    RuntimeMatcher::GeoipCountry { country_codes } => {
                        RequesterTest::Country(country_codes.clone())
                    }
                    RuntimeMatcher::EdnsPresent { .. } => RequesterTest::Edns,
                    _ => continue,
                };
                reads.request_matchers.add(test);
            }
            answer_edns |= response_matchers.iter().any(|m| {
                matches!(
                    m.matcher,
                    RuntimeResponseMatcher::ResponseEdnsPresent { .. }
                )
            });
            // 规则自己的转发和回答动作里的转发都可能按客户端地址发 ECS，回答动作里的照它自己写的 `ecs` 发
            // The rule's own forward and the forwards among its answer actions may each send ECS
            // by the client's address, those among the answer actions by the `ecs` they write
            for test in rule.actions.iter().filter_map(subnet) {
                reads.forward_subnets.add(test);
            }
            for test in on_match.iter().chain(on_miss).filter_map(subnet) {
                reads.forward_subnets.add(test.clone());
                reads.answer_subnets.add(test);
            }
            let jump_target = |action: &Action| match action {
                Action::JumpToPipeline { pipeline } => Some(Arc::clone(pipeline)),
                _ => None,
            };
            for target in on_match.iter().chain(on_miss).filter_map(jump_target) {
                reads.response_jumps.push(target.clone());
                reads.jumps.push(target);
            }
            for target in rule.actions.iter().filter_map(jump_target) {
                if continued {
                    reads.continued_jumps.push(target.clone());
                }
                reads.jumps.push(target);
            }
            continued |= on_match
                .iter()
                .chain(on_miss)
                .any(|action| matches!(action, Action::Continue));
        }
        reads.matchers = reads.request_matchers.clone();
        if answer_edns {
            reads.matchers.add(RequesterTest::Edns);
        }
        reads
    }
}

/// Every pipeline reachable from `starts` by `jump_to_pipeline`, in rule actions
/// or answer checks, `starts` included / 从 `starts` 经规则动作或回答检查里的
/// `jump_to_pipeline` 能到达的每个 pipeline，含 `starts` 本身
fn reachable_pipelines(
    reads: &[RuleReads],
    index: &FxHashMap<Arc<str>, usize>,
    starts: impl IntoIterator<Item = usize>,
) -> Vec<usize> {
    let mut seen = vec![false; reads.len()];
    let mut stack: Vec<usize> = starts.into_iter().collect();
    let mut reached = Vec::new();
    while let Some(idx) = stack.pop() {
        if std::mem::replace(&mut seen[idx], true) {
            continue;
        }
        reached.push(idx);
        stack.extend(
            reads[idx]
                .jumps
                .iter()
                .filter_map(|target| index.get(target).copied()),
        );
    }
    reached
}

/// Each pipeline's scope (see `RuntimePipeline::requester`) / 每个 pipeline 的范围
fn requester_scopes(
    reads: &[RuleReads],
    index: &FxHashMap<Arc<str>, usize>,
    answered_through: &[Vec<usize>],
) -> Vec<RequesterScope> {
    (0..reads.len())
        .map(|idx| {
            let mut scope = reads[idx].matchers.clone();
            scope.extend(&reads[idx].forward_subnets);
            // 转发之后回答检查可能跳转，或者 continue 到会跳转的规则，请求运行这些路径上的规则，之后等待者（见
            // `Route::held_inflight`）拿到应答，应答也缓存在这个 pipeline 的键下（见
            // `RuntimePipeline::answered_through`）：那里的匹配器计入。回答检查跳转路径上规则自己的转发原样发出这个
            // pipeline 的转发发出的包（它的子网上面已经计入），那里回答动作里自己写了 `ecs` 的转发却照它从客户端的
            // 查询改写（见 `engine::rules::run_response_actions`），所以它的子网也计入。
            // After a forward, an answer check may jump, or continue to rules that jump, and
            // the request runs the rules along those paths before its waiters (see
            // `Route::held_inflight`), and the cache under this pipeline's key, take the
            // answer (see `RuntimePipeline::answered_through`): their matchers count. A rule's
            // own forward on an answer check's jump path sends the packet this pipeline's
            // forward sent as it is (its subnet counted above), while a forward among the
            // answer actions there with an `ecs` of its own rewrites the client's query by it
            // (see `engine::rules::run_response_actions`), so its subnets count too.
            for &reached in &answered_through[idx] {
                scope.extend(&reads[reached].matchers);
                scope.extend(&reads[reached].answer_subnets);
            }
            // continue 之后跳到的转发发送自己的 ECS，本 pipeline 的键本来不带着，所以它们的子网都计入。
            // Forwards reached by a jump after a continue send their own ECS, which this
            // pipeline's key does not carry otherwise, so all their subnets count.
            let targets = reads[idx]
                .continued_jumps
                .iter()
                .filter_map(|target| index.get(target).copied());
            for reached in reachable_pipelines(reads, index, targets) {
                scope.extend(&reads[reached].forward_subnets);
            }
            scope
        })
        .collect()
}

/// 按各 pipeline 的规则读什么（`reads`，和 `pipelines` 一一对应），给每个 pipeline 填上它分辨请求方的依据、据过上游的回答
/// 以后跳到的 pipeline（见 `RuntimePipeline::answered_through`）、规则阶段的依据和用到的 Geo 数据；`index` 按 id 找
/// pipeline 的位置
/// From what each pipeline's rules read (`reads`, one for each of `pipelines`), fill in every
/// pipeline's way of telling requesters apart, the pipelines it jumps to once an upstream's
/// answer has been gone by (see `RuntimePipeline::answered_through`), what its rules alone read,
/// and the Geo data it uses; `index` finds a pipeline's place by its id
pub(super) fn fill_requester_scopes(
    pipelines: &mut [RuntimePipeline],
    reads: &[RuleReads],
    pipeline_id_index: &FxHashMap<Arc<str>, usize>,
) {
    let answered_through: Vec<Vec<usize>> = reads
        .iter()
        .map(|rule_reads| {
            let targets = rule_reads
                .response_jumps
                .iter()
                .chain(&rule_reads.continued_jumps)
                .filter_map(|target| pipeline_id_index.get(target).copied());
            reachable_pipelines(reads, pipeline_id_index, targets)
        })
        .collect();
    let scopes = requester_scopes(reads, pipeline_id_index, &answered_through);
    for (((pipeline, scope), rule_reads), through) in pipelines
        .iter_mut()
        .zip(scopes)
        .zip(reads)
        .zip(answered_through)
    {
        pipeline.requester = scope;
        pipeline.rule_requester = rule_reads.request_matchers.clone();
        // 这个 pipeline 的键下缓存的是它自己的规则给的，和回答检查跳过去、continue 以后的规则跳过去拿到的；别的请求阶段
        // 跳转拿到的应答缓存在目标的键下（见 `engine::execution::Route::enter`），不随目标读的数据换命名空间
        // Cached under this pipeline's keys are what its own rules give and what is got by its
        // answer checks' jumps and by the jumps of its rules after a continue; the answers any
        // other request-phase jump gets are cached under the target's keys (see
        // `engine::execution::Route::enter`), so the data that target reads does not move this
        // namespace
        let mut geo = rule_reads.geo.clone();
        for &reached in &through {
            geo.extend(&reads[reached].geo);
        }
        pipeline.geo_data = geo;
        pipeline.answered_through = through;
    }
}
