//! 谁在问：规则能分辨的请求方（地址、带不带 EDNS、客户端自己的 ECS），规则区分它们的依据（`RequesterTest`），
//! 一个 pipeline 连同它跳得到的 pipeline 合起来的依据（`RequesterScope`），以及缓存和 inflight 键里请求方那一部分
//! (`RequesterKey`)
//! Who is asking: the requester as far as rules can tell (address, EDNS or not, the client's own
//! ECS), what rules tell requesters apart by (`RequesterTest`), what a pipeline with those it can
//! jump to tells them apart by (`RequesterScope`), and the requester's part of the cache and
//! inflight keys (`RequesterKey`)

use super::*;
/// Who is asking, as far as rules can tell.
/// 规则能分辨的请求方。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Requester {
    /// The client's address / 客户端地址
    pub address: IpAddr,
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
        geoip_manager: Option<&Arc<parking_lot::RwLock<geoip::GeoIpManager>>>,
        hasher: &mut H,
    ) {
        match self {
            Self::InNet(net) => net.contains(&requester.address).hash(hasher),
            Self::Private => geoip::is_private_ip(requester.address).hash(hasher),
            Self::Country(codes) => geoip_manager
                .is_some_and(|manager| manager.read().matches_any_tag(requester.address, codes))
                .hash(hasher),
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

    /// The requester's part of a key: how each test judges `requester`. Empty
    /// for a scope without tests.
    /// 键里属于请求方的部分：每项依据对 `requester` 的判定。没有依据时为空。
    pub fn key(
        &self,
        requester: Requester,
        geoip_manager: Option<&Arc<parking_lot::RwLock<geoip::GeoIpManager>>>,
    ) -> RequesterKey {
        let judge = |subnets: bool| {
            let mut tests = self
                .tests
                .iter()
                .filter(|test| matches!(test, RequesterTest::Subnet { .. }) == subnets)
                .peekable();
            tests.peek()?;
            let mut hasher = rustc_hash::FxHasher::default();
            for test in tests {
                test.hash_outcome(requester, geoip_manager, &mut hasher);
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
    /// Pipelines its answer checks jump to / 回答检查跳到的 pipeline
    response_jumps: Vec<Arc<str>>,
    /// Pipelines its rules jump to / 规则跳到的 pipeline
    request_jumps: Vec<Arc<str>>,
    /// Pipelines its rules or answer checks jump to / 规则或回答检查跳到的 pipeline
    jumps: Vec<Arc<str>>,
    /// Whether an answer check continues / 是否有回答检查会 continue
    continues: bool,
    /// The Geo data its rules read / 规则读的 Geo 数据
    geo: GeoData,
}

impl RuleReads {
    pub(super) fn of(rules: &[RuntimeRule]) -> Self {
        let mut reads = Self {
            request_matchers: RequesterScope::default(),
            matchers: RequesterScope::default(),
            forward_subnets: RequesterScope::default(),
            response_jumps: Vec::new(),
            request_jumps: Vec::new(),
            jumps: Vec::new(),
            continues: false,
            geo: GeoData::default(),
        };
        let mut answer_edns = false;
        for rule in rules {
            let (response_matchers, on_match, on_miss) =
                ResponsePhase::parts(rule.response_phase.as_deref());
            // 请求匹配器读的 GeoIP 只按客户端地址判断，不算（见 [`GeoData`]）/ The GeoIP request
            // matchers read judges the client address alone and does not count (see [`GeoData`])
            reads.geo.site |= rule
                .matchers
                .iter()
                .any(|m| matches!(m.matcher.geo_tags(), Some(GeoTags::Site(_))));
            for tags in response_matchers
                .iter()
                .filter_map(|m| m.matcher.geo_tags())
            {
                match tags {
                    GeoTags::Site(_) => reads.geo.site = true,
                    GeoTags::Ip(_) => reads.geo.ip = true,
                }
            }
            for m in rule.matchers.iter() {
                let test = match &m.matcher {
                    RuntimeMatcher::ClientIp { net } => RequesterTest::InNet(*net),
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
            // 规则自己的转发和回答动作里的转发都可能按客户端地址发 ECS：回答动作里的照它自己写的 `ecs` 发。以前只看规则
            // 自己的，两台不同网段的客户端同时问，后来的那台合并进先来的那台的条目，拿到按先来的那台网段取回的应答
            // The rule's own forward and the forwards among its answer actions may each send ECS by
            // the client's address, those among the answer actions by the `ecs` they write. Only
            // the rule's own used to count, so of two clients in different networks asking at once
            // the later merged into the earlier's entry and got the answer fetched for the
            // earlier's network
            for action in rule.all_actions() {
                if let Action::Forward {
                    ecs:
                        Some(config::EcsMode::FromClientIp {
                            prefix_v4,
                            prefix_v6,
                        }),
                    ..
                } = action
                {
                    reads.forward_subnets.add(RequesterTest::Subnet {
                        prefix_v4: *prefix_v4,
                        prefix_v6: *prefix_v6,
                    });
                }
            }
            reads.continues |= on_match
                .iter()
                .chain(on_miss)
                .any(|action| matches!(action, Action::Continue));
            let jump_target = |action: &Action| match action {
                Action::JumpToPipeline { pipeline } => Some(Arc::clone(pipeline)),
                _ => None,
            };
            for target in on_match.iter().chain(on_miss).filter_map(jump_target) {
                reads.response_jumps.push(target.clone());
                reads.jumps.push(target);
            }
            for target in rule.actions.iter().filter_map(jump_target) {
                reads.request_jumps.push(target.clone());
                reads.jumps.push(target);
            }
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
            // After a forward, an answer check may jump, and the request runs the
            // rules along the jump path before its waiters, and the cache under this
            // pipeline's key, take the answer. Forwards there send the packet this
            // pipeline's forward sent as it is (its subnet counted above), so only
            // matchers count.
            // 转发之后回答检查可能跳转，请求运行跳转路径上的规则，之后等待者拿到应答，应答也缓存在
            // 这个 pipeline 的键下。那里的转发原样发出这个 pipeline 的转发发出的包（它的子网上面已经
            // 计入），所以只有匹配器计入。
            for &reached in &answered_through[idx] {
                scope.extend(&reads[reached].matchers);
            }
            // After an answer check continues, the request keeps its entry for the
            // rest of the decision loop (see `ForwardDecisionContext::held_inflight`)
            // and its waiters take the final answer. The rest of the pipeline and
            // the pipelines it jumps to may decide that answer, and forwards there
            // send their own ECS, which this pipeline's key does not carry.
            // 回答检查 continue 之后，请求在决策循环余下的部分一直持有条目（见
            // `ForwardDecisionContext::held_inflight`），等待者拿到最终应答。这个应答可能由
            // pipeline 余下的规则和它跳到的 pipeline 决定，而那里的转发发送自己的 ECS，
            // 本 pipeline 的键并不带着。
            if reads[idx].continues {
                let targets = reads[idx]
                    .request_jumps
                    .iter()
                    .filter_map(|target| index.get(target).copied());
                for reached in reachable_pipelines(reads, index, targets) {
                    scope.extend(&reads[reached].matchers);
                    scope.extend(&reads[reached].forward_subnets);
                }
            }
            scope
        })
        .collect()
}

/// 按各 pipeline 的规则读什么（`reads`，和 `pipelines` 一一对应），给每个 pipeline 填上它分辨请求方的依据、回答阶段跳到的
/// pipeline、规则阶段的依据和用到的 Geo 数据；`index` 按 id 找 pipeline 的位置
/// From what each pipeline's rules read (`reads`, one for each of `pipelines`), fill in every
/// pipeline's way of telling requesters apart, the pipelines its answer checks jump to, what its
/// rules alone read, and the Geo data it uses; `index` finds a pipeline's place by its id
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
        // 这个 pipeline 的键下缓存的是它自己的规则给的，和回答检查跳过去拿到的；请求阶段跳过去的应答缓存在目标的键下
        // （见 `engine::execution::Route::enter`），不随目标读的数据换命名空间
        // Cached under this pipeline's keys are what its own rules give and what its answer
        // checks' jumps get; the answers a request-phase jump gets are cached under the
        // target's keys (see `engine::execution::Route::enter`), so the data the target reads
        // does not move this namespace
        pipeline.geo_data = through
            .iter()
            .fold(rule_reads.geo, |geo, &reached| geo.with(reads[reached].geo));
        pipeline.answered_through = through;
    }
}
