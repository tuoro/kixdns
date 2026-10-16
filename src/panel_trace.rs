use std::cell::RefCell;
use std::future::Future;
use std::time::Instant;

use serde::Serialize;

use crate::observe::{DecisionDetail, DecisionMade};

const MAX_STEPS: usize = 128;
const MAX_LABEL_BYTES: usize = 256;
const MAX_DETAIL_BYTES: usize = 1_024;

#[derive(Clone, Debug, Serialize)]
pub struct TraceStep {
    pub stage: &'static str,
    pub status: &'static str,
    pub label: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    pub elapsed_ms: u64,
}

struct Collector {
    started: Instant,
    steps: Vec<TraceStep>,
    truncated: bool,
    pipeline: Option<String>,
    decision_rule: Option<String>,
    decision_transport: Option<String>,
}

tokio::task_local! {
    static TRACE: RefCell<Collector>;
}

pub async fn capture<F>(future: F) -> (F::Output, Vec<TraceStep>, bool)
where
    F: Future,
{
    TRACE
        .scope(
            RefCell::new(Collector {
                started: Instant::now(),
                steps: Vec::new(),
                truncated: false,
                pipeline: None,
                decision_rule: None,
                decision_transport: None,
            }),
            async move {
                let output = future.await;
                let (steps, truncated) = TRACE.with(|trace| {
                    let mut trace = trace.borrow_mut();
                    (std::mem::take(&mut trace.steps), trace.truncated)
                });
                (output, steps, truncated)
            },
        )
        .await
}

/// 记一步诊断轨迹，只在诊断查询正在记录时才拼说明文字。每个普通查询都要经过观察者的这些回调，
/// 先拼好、因为不是诊断又丢掉的字符串，原来占了回调开销里不小的一块。
/// Records one diagnostics trace step, building its text only while a diagnostic query is
/// recording. Every ordinary query passes through these observer callbacks, and strings built
/// only to be dropped because no diagnosis was running were a sizeable share of their cost.
macro_rules! trace_step {
    ($stage:expr, $status:expr, $label:expr, $detail:expr $(,)?) => {
        if $crate::panel_trace::active() {
            $crate::panel_trace::record($stage, $status, $label, $detail);
        }
    };
}
pub(crate) use trace_step;

pub fn record(
    stage: &'static str,
    status: &'static str,
    label: impl Into<String>,
    detail: Option<String>,
) {
    let _ = TRACE.try_with(|trace| {
        let mut trace = trace.borrow_mut();
        if trace.steps.len() >= MAX_STEPS {
            trace.truncated = true;
            return;
        }
        let elapsed_ms = u64::try_from(trace.started.elapsed().as_millis()).unwrap_or(u64::MAX);
        trace.steps.push(TraceStep {
            stage,
            status,
            label: truncate(label.into(), MAX_LABEL_BYTES),
            detail: detail.map(|value| truncate(value, MAX_DETAIL_BYTES)),
            elapsed_ms,
        });
    });
}

pub fn record_decision(event: &DecisionMade<'_>) {
    // 不在诊断时什么也不记：下面的说明文字不必拼 / Outside a diagnosis nothing is recorded, so the text below need not be built
    if !active() {
        return;
    }
    match event.detail {
        DecisionDetail::Static { rcode, answers } => record(
            "decision",
            "selected",
            format!("静态响应 {rcode}"),
            Some(format!("答案记录数：{answers}")),
        ),
        DecisionDetail::Forward {
            upstream,
            transport,
        } => {
            let rule = event.rule.unwrap_or("default");
            let _ = TRACE.try_with(|trace| {
                let mut trace = trace.borrow_mut();
                trace.decision_rule = Some(rule.to_owned());
                trace.decision_transport = Some(format!("{transport:?}"));
            });
            record(
                "decision",
                "selected",
                format!("规则 {rule} 转发"),
                Some(format!("目标：{upstream}；传输：{transport:?}")),
            )
        }
        DecisionDetail::Jump { pipeline } => record(
            "decision",
            "selected",
            format!("跳转到管线 {pipeline}"),
            None,
        ),
    }
}

/// 记录当前请求最近选中的管线，供缺少管线上下文的事件补充明细。
/// 当前任务是否在诊断作用域里：诊断查询不进查询排行，免得测试用的域名和客户端 IP 混进统计
/// Whether the current task runs inside a diagnostic scope: diagnostic queries stay out of the
/// query ranking, so test domains and client IPs never mix into the statistics
pub fn active() -> bool {
    TRACE.try_with(|_| ()).is_ok()
}

pub fn set_pipeline(pipeline: &str) {
    let _ = TRACE.try_with(|trace| {
        trace.borrow_mut().pipeline = Some(pipeline.to_owned());
    });
}

/// 最近一次转发决策的规则名与传输描述，供上游步骤补充明细。
pub fn current_decision() -> (Option<String>, Option<String>) {
    TRACE
        .try_with(|trace| {
            let trace = trace.borrow();
            (
                trace.decision_rule.clone(),
                trace.decision_transport.clone(),
            )
        })
        .unwrap_or((None, None))
}

pub fn current_pipeline() -> Option<String> {
    TRACE
        .try_with(|trace| trace.borrow().pipeline.clone())
        .ok()
        .flatten()
}

fn truncate(mut value: String, limit: usize) -> String {
    if value.len() <= limit {
        return value;
    }
    let mut boundary = limit.saturating_sub(3);
    while !value.is_char_boundary(boundary) {
        boundary = boundary.saturating_sub(1);
    }
    value.truncate(boundary);
    value.push_str("...");
    value
}

#[cfg(test)]
mod tests {
    use super::{MAX_STEPS, capture, record};
    use std::cell::Cell;

    /// 不在诊断时，说明文字连拼都不拼；在诊断里照常拼、照常记
    /// Outside a diagnosis the text is not even built; inside one it is built and recorded as before
    #[tokio::test]
    async fn trace_text_is_built_only_while_a_diagnosis_records() {
        let built = Cell::new(0);
        let label = || {
            built.set(built.get() + 1);
            "step".to_owned()
        };
        trace_step!("stage", "status", label(), None);
        assert_eq!(built.get(), 0, "no diagnosis: nothing built");
        let ((), steps, _) = capture(async {
            trace_step!("stage", "status", label(), Some(label()));
        })
        .await;
        assert_eq!(built.get(), 2, "label and detail built once each");
        assert_eq!(steps.len(), 1);
        assert_eq!(steps[0].label, "step");
        assert_eq!(steps[0].detail.as_deref(), Some("step"));
    }

    #[tokio::test]
    async fn captures_bounded_steps_only_inside_scope() {
        record("outside", "ignored", "ignored", None);
        let (value, steps, truncated) = capture(async {
            for index in 0..=MAX_STEPS {
                record("rule", "checked", format!("rule-{index}"), None);
            }
            7
        })
        .await;
        assert_eq!(value, 7);
        assert_eq!(steps.len(), MAX_STEPS);
        assert!(truncated);
    }
}
