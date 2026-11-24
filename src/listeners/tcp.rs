//! TCP 监听器：每条连接读出按长度前缀分好的查询，当场答得上的攒起来一起写出，要等上游的各自起任务（RFC 7766）
//! The TCP listener: each connection reads queries framed by length prefixes, writes those answered on the
//! spot out together, and gives each that waits on an upstream a task of its own (RFC 7766)

use crate::engine::{Engine, OnTheSpot};
use crate::observe::ClientTransport;
use crate::proto_utils::{MAX_QUERY_LEN, servfail_reply};
use std::borrow::Cow;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, TcpStream};
use tracing::warn;

/// 在 `listener` 上接 TCP 连接，一直接下去，不返回 / Accepts TCP connections on `listener` for good, never
/// returning
pub(super) async fn run_tcp(listener: TcpListener, engine: Engine) -> ! {
    // 一个监听口一份引擎，连接之间共享不复制：每条连接只加一次引用计数，不复制整个 Engine（二十多个 Arc）
    // One engine per listener, shared between connections rather than copied: each connection
    // takes one reference count instead of a copy of the whole Engine (twenty-odd Arcs)
    let engine = Arc::new(engine.with_client_transport(ClientTransport::Tcp));
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(accepted) => accepted,
            Err(err) => {
                // Never end the loop on an accept error (see accept_retry_delay)
                // 接受出错不退出循环（见 accept_retry_delay）
                warn!(error = %err, "tcp accept failed, retrying");
                tokio::time::sleep(crate::socket_utils::accept_retry_delay(&err)).await;
                continue;
            }
        };
        // RFC 1035 §4.2.2: DNS-over-TCP uses a 2-byte length prefix per message.
        // Disable Nagle's algorithm (TCP_NODELAY) to prevent the length-prefix write
        // and body write from being coalesced, which interacts badly with the peer's
        // delayed-ACK timer and adds ~40 ms latency per query.
        //
        // 禁用 Nagle 算法 (TCP_NODELAY)，避免长度前缀和包体两次写入被合并，
        // 否则与对端的 delayed-ACK 定时器交互导致每查询约 40ms 延迟。
        stream.set_nodelay(true).ok();
        // 内存不够时不接新连接，已有的连接照常 / With too little memory no new connection is taken, and those there go on
        let Some(permit) = engine.connection_permit(peer.ip()) else {
            continue;
        };
        let engine = Arc::clone(&engine);
        tokio::spawn(async move {
            let _permit = permit;
            handle_tcp_conn(stream, peer, engine).await;
        });
    }
}

/// 入站 TCP 连接等待下一条消息、或等待当前消息剩余字节的时限。RFC 7766 §6.2.3
/// 建议服务端对空闲连接设数秒量级的超时：只建立连接却不发数据的客户端不应长期
/// 占用一个任务和一个文件描述符，而正常客户端在一个 RTT 内就会发完一条消息。
/// Time an inbound TCP connection may take to send the next message, or the rest
/// of the current one. RFC 7766 §6.2.3 recommends a server idle timeout in the
/// order of seconds: a client that connects without sending should not pin a
/// task and a file descriptor, while a normal client finishes a message within
/// one round trip.
pub(super) const TCP_READ_TIMEOUT: Duration = Duration::from_secs(10);

/// 同一条入站 TCP 连接上最多同时处理这么多个查询。RFC 7766 第 6.2.1.1 节：流水线发来的查询要并发
/// 处理、答完就回；以前一个接一个地处理，一个慢查询把后面的快查询都挡住。满了就先不读下一个，一个
/// 客户端开不出没有上限的任务。
/// At most this many queries are handled at once on one inbound TCP connection. RFC 7766
/// section 6.2.1.1: pipelined queries are handled concurrently and answered as they complete;
/// they used to be handled one after another, a slow one holding up every fast one behind
/// it. With all slots taken the next query is not read yet, so one client cannot start an
/// unbounded number of tasks.
pub(super) const TCP_MAX_QUERIES_PER_CONN: usize = 64;

/// 一次至少读这么多：流水线发来的几个查询一次读进来，不再每个查询读两次（长度前缀、正文）
/// Each read asks for at least this much: queries pipelined together come in with one read,
/// instead of two reads (length prefix, body) per query
pub(super) const TCP_READ_CHUNK: usize = 4096;

/// 当场答好的回答攒到这么多就先写出去，不等这一批读完 / Answers made on the spot are written out
/// once this much has gathered, without waiting for the rest of the batch
const TCP_ANSWERS_FLUSH: usize = 16 * 1024;

/// 读进来的字节里的下一个消息（见 [`take_tcp_message`]）/ The next message in the bytes read (see
/// [`take_tcp_message`])
enum TcpMessage {
    /// 收全了，不带长度前缀，拷成单独的一份 / Complete, without its length prefix, copied into a
    /// piece of its own
    Message(bytes::Bytes),
    /// 还差这么多字节才收全 / This many bytes short of complete
    Missing(usize),
    /// 声明的长度超过 [`MAX_QUERY_LEN`]：没有这么长的查询，不等它、也不答它 / Declaring more than
    /// [`MAX_QUERY_LEN`]: no query is this long, and it is neither waited for nor answered
    TooLong,
}

/// 从读进来的字节里取出下一个消息；长度前缀只在这里读。查询只有几十到几百字节，拷出来不费事：在途的查询不钉住整块读缓冲，
/// 读缓冲留在原地接着用，不必每读一轮都另分配一块
/// Takes the next message out of the bytes read; the length prefix is read here alone. A query
/// is a few tens to hundreds of bytes and cheap to copy: the queries in flight do not pin the
/// whole read buffer, which stays where it is for the next reads instead of a new one being
/// allocated each round
fn take_tcp_message(received: &mut bytes::BytesMut) -> TcpMessage {
    use bytes::Buf;

    let Some(&prefix) = received.first_chunk::<2>() else {
        return TcpMessage::Missing(2 - received.len());
    };
    let len = usize::from(u16::from_be_bytes(prefix));
    if len > MAX_QUERY_LEN {
        return TcpMessage::TooLong;
    }
    let Some(body) = received.get(2..2 + len) else {
        return TcpMessage::Missing(2 + len - received.len());
    };
    let message = bytes::Bytes::copy_from_slice(body);
    received.advance(2 + len);
    TcpMessage::Message(message)
}

/// 能放进一个 TCP 消息的回答：长度前缀只有两个字节（RFC 1035 第 4.2.2 节），超过 65535 字节的换成这个查询的 SERVFAIL（见
/// `proto_utils::servfail_reply`）。以前这样的回答不发，客户端一直等到超时
/// The answer as it fits in one TCP message: the length prefix has two bytes (RFC 1035 section
/// 4.2.2), and one over 65535 bytes gives way to the query's SERVFAIL (see
/// `proto_utils::servfail_reply`). Such an answer used to go unsent, the client waiting until
/// it timed out
fn tcp_answer<'a>(query: &[u8], answer: &'a [u8]) -> Cow<'a, [u8]> {
    if answer.len() > usize::from(u16::MAX) {
        Cow::Owned(servfail_reply(query).into())
    } else {
        Cow::Borrowed(answer)
    }
}

/// 当场答好的一个回答带上长度前缀排进 `answers`（见 [`tcp_answer`]）/ Queues one answer made on the
/// spot into `answers` with its length prefix (see [`tcp_answer`])
fn queue_tcp_answer(answers: &mut bytes::BytesMut, query: &[u8], response: &[u8]) {
    let response = tcp_answer(query, response);
    answers.extend_from_slice(&(response.len() as u16).to_be_bytes());
    answers.extend_from_slice(&response);
}

pub(super) async fn handle_tcp_conn(stream: TcpStream, peer: SocketAddr, engine: Arc<Engine>) {
    serve_tcp_conn(stream, peer, engine, TCP_READ_TIMEOUT).await
}

/// 处理一条入站 TCP 连接；等下一个消息的长度前缀、等当前消息的正文，各最多 `read_timeout`（测试用短的）
/// Handles one inbound TCP connection; waiting for the next message's length prefix, and for the
/// current message's body, each take at most `read_timeout` (short in tests)
pub(super) async fn serve_tcp_conn(
    stream: TcpStream,
    peer: SocketAddr,
    engine: Arc<Engine>,
    read_timeout: Duration,
) {
    let (mut reader, writer) = stream.into_split();
    let writer = Arc::new(TcpWriter {
        half: tokio::sync::Mutex::new(writer),
        broken: tokio_util::sync::CancellationToken::new(),
    });
    let slots = Arc::new(tokio::sync::Semaphore::new(TCP_MAX_QUERIES_PER_CONN));
    let mut pending = tokio::task::JoinSet::<()>::new();
    // 读进来还没处理的字节：一次读到的可能是好几个查询，也可能是半个
    // Bytes read but not handled yet: one read may bring several queries, or half of one
    let mut received = bytes::BytesMut::with_capacity(TCP_READ_CHUNK);
    // 当场答好、还没写出去的回答，带着长度前缀；下一次读之前一次写出去
    // Answers made on the spot, with their length prefixes, not yet written; written in one go
    // before the next read
    let mut answers = bytes::BytesMut::new();
    // 复用的缓冲：快速路径当场答的写在这里（见 `Engine::on_the_spot`）/ Reused buffer the fast path writes
    // what it answers on the spot to (see `Engine::on_the_spot`)
    let mut spot = bytes::BytesMut::new();
    // 正在等的是不是正文、等到什么时候：长度前缀和正文各有 read_timeout
    // Whether a body is being waited for, and until when: the length prefix and the body
    // each get read_timeout
    let mut waiting: Option<(bool, tokio::time::Instant)> = None;

    'connection: loop {
        if writer.broken.is_cancelled() {
            break;
        }
        // 收掉已经答完的 / Reap the ones already answered
        while pending.try_join_next().is_some() {}

        // 读进来的完整消息一个个处理：当场能答的排进 answers，要等上游的交给单独的任务，答完就回；剩下的不完整时记下还差
        // 多少，声明得太长时关掉连接
        // Every complete message read is handled in turn: what is answered on the spot is
        // queued in answers, and what waits on an upstream goes to its own task, answered when
        // done; what is left incomplete notes how much it is short, and one declared too long
        // closes the connection
        let missing = loop {
            let packet_bytes = match take_tcp_message(&mut received) {
                TcpMessage::Message(packet_bytes) => packet_bytes,
                TcpMessage::Missing(missing) => break missing,
                TcpMessage::TooLong => break 'connection,
            };
            waiting = None;
            let async_needed = match engine.on_the_spot(&packet_bytes, peer, &mut spot) {
                OnTheSpot::Reply => {
                    queue_tcp_answer(&mut answers, &packet_bytes, &spot);
                    None
                }
                OnTheSpot::Forward(pre_parsed) => Some(pre_parsed),
                // 应答不是查询，断开 / A response is no query, and the connection closes
                OnTheSpot::Drop => break 'connection,
            };
            if answers.len() >= TCP_ANSWERS_FLUSH {
                write_tcp_answers(&writer, &mut answers).await;
            }
            let Some(pre_parsed) = async_needed else {
                continue;
            };
            let Some(permit) = engine.query_permit(None, peer.ip()) else {
                queue_tcp_answer(&mut answers, &packet_bytes, &servfail_reply(&packet_bytes));
                continue;
            };

            // 满了就先不读下一个；等之前把已经答好的写出去，它们不陪着等
            // With all slots taken the next query is not read yet; what is already answered
            // is written out first instead of waiting along
            let slot = match Arc::clone(&slots).try_acquire_owned() {
                Ok(slot) => slot,
                Err(_) => {
                    write_tcp_answers(&writer, &mut answers).await;
                    let Ok(slot) = Arc::clone(&slots).acquire_owned().await else {
                        break 'connection;
                    };
                    slot
                }
            };
            let engine = Arc::clone(&engine);
            let writer = Arc::clone(&writer);
            pending.spawn(async move {
                let _slot = slot;
                let _permit = permit;
                let answer = engine
                    .answer_after_fast_path(&packet_bytes, peer, pre_parsed)
                    .await;
                write_tcp_answer(&writer, &packet_bytes, &answer).await;
            });
        };
        write_tcp_answers(&writer, &mut answers).await;

        // 读更多：至少要够把当前这个消息读完 / Read more: at least enough to finish the current message
        received.reserve(missing.max(TCP_READ_CHUNK));
        let in_body = received.len() >= 2;
        // 等下一个查询、手上还有查询在等上游回答时不算空闲：读不设时限，等哪个答完再重新算，空闲从再没有查询要等的那一刻
        // 起算。以前照样计时，上游慢时等回答的那段时间里再来的查询躺在接收缓冲里没人读，答完一关连接就丢了。半截消息的
        // 时限照旧
        // Waiting for the next query with queries still waiting on an upstream is no idleness: the
        // read has no deadline, worked out again once one is answered, and idleness counts from when
        // none is left waiting. It used to be timed all the same, and with a slow upstream a query
        // sent meanwhile lay unread in the receive buffer, lost as the connection closed after the
        // answer. A half-sent message keeps its deadline
        let answering = !in_body && !pending.is_empty();
        let deadline = (!answering).then(|| match waiting {
            Some((body, deadline)) if body == in_body => deadline,
            _ => {
                let deadline = tokio::time::Instant::now() + read_timeout;
                waiting = Some((in_body, deadline));
                deadline
            }
        });
        // 空闲超时、半截消息超时、对方读到头或出错：不再读，还在处理的查询写完回答后关闭连接，
        // 释放任务与文件描述符
        // Idle timeout, a half-sent message timing out, the peer's end of stream or an error:
        // reading stops, and once the queries still being handled have written their answers
        // the connection closes, releasing the task and the file descriptor
        let read = tokio::select! {
            _ = writer.broken.cancelled() => break,
            _ = pending.join_next(), if answering => {
                waiting = None;
                continue;
            }
            read = async {
                match deadline {
                    Some(deadline) => {
                        tokio::time::timeout_at(deadline, reader.read_buf(&mut received)).await
                    }
                    None => Ok(reader.read_buf(&mut received).await),
                }
            } => read,
        };
        if !matches!(read, Ok(Ok(1..))) {
            break;
        }
    }

    // 写端坏了：还在等上游的查询不必再等，它们的回答写不出去了（丢掉 pending 时一起取消）
    // The write side broke: the queries still waiting on an upstream need wait no more, their
    // answers having nowhere to go (cancelled as `pending` is dropped)
    if writer.broken.is_cancelled() {
        return;
    }
    // 读完了：先把当场答好的写出去，再等还在处理的查询把回答写出去，然后关连接；半关闭的客户端照样拿到回答
    // Reading is over: what was answered on the spot is written first, then the queries still
    // being handled write their answers before the connection closes, so a half-closed client
    // still gets them
    write_tcp_answers(&writer, &mut answers).await;
    while pending.join_next().await.is_some() {}
}

/// 一条入站 TCP 连接的写端，和它坏没坏：写不出去（或 [`TCP_READ_TIMEOUT`] 内写不完，对方不读）时关掉写端、记下坏了。
/// 读的那边见了就不再读，还在等上游的查询也不再等。以前只关写端，读循环照样解析、问上游，要等空闲满读取时限才退出，
/// 一个只发不读的客户端能让服务端一直白干活
/// The write side of one inbound TCP connection, and whether it broke: when an answer cannot be
/// written, or not within [`TCP_READ_TIMEOUT`] (the peer does not read), the write side is shut
/// and noted broken. Seeing that, the reading side reads no more and the queries waiting on an
/// upstream wait no more. Only the write side used to be shut, the read loop parsing and asking
/// upstreams as before until idle for the whole read timeout, so a client sending without ever
/// reading kept the server working for nothing
struct TcpWriter {
    half: tokio::sync::Mutex<tokio::net::tcp::OwnedWriteHalf>,
    broken: tokio_util::sync::CancellationToken,
}

impl TcpWriter {
    /// 关掉写端，记下坏了 / Shuts the write side and notes it broken
    async fn shut(&self, half: &mut tokio::net::tcp::OwnedWriteHalf) {
        use tokio::io::AsyncWriteExt;
        let _ = half.shutdown().await;
        self.broken.cancel();
    }
}

/// 把排好的回答一次写出去，和 [`write_tcp_answer`] 一样：写端加锁，不和别的回答穿插；写不出去或
/// [`TCP_READ_TIMEOUT`] 内写不完时关掉写端
/// Writes the queued answers in one go, like [`write_tcp_answer`]: under the writer's lock, so
/// they cannot interleave with another answer; when they cannot be written, or not within
/// [`TCP_READ_TIMEOUT`], the write side is shut
async fn write_tcp_answers(writer: &TcpWriter, answers: &mut bytes::BytesMut) {
    use tokio::io::AsyncWriteExt;

    if answers.is_empty() || writer.broken.is_cancelled() {
        answers.clear();
        return;
    }
    let mut half = writer.half.lock().await;
    let written = tokio::time::timeout(TCP_READ_TIMEOUT, half.write_all(answers)).await;
    if !matches!(written, Ok(Ok(()))) {
        writer.shut(&mut half).await;
    }
    answers.clear();
}

/// 写回 `query` 的一个回答（见 [`tcp_answer`]）：长度前缀加正文一次写完，写端加锁，不会和别的回答穿插。写不出去或
/// [`TCP_READ_TIMEOUT`] 内写不完（对方不读）时关掉写端：后面的回答立刻失败，任务不会一个个卡在这里。
/// Writes one answer to `query` back (see [`tcp_answer`]): length prefix and body in one go
/// under the writer's lock, so it cannot interleave with another answer. When it cannot be
/// written, or not within [`TCP_READ_TIMEOUT`] (the peer does not read), the write side is
/// shut: later answers fail at once instead of each task getting stuck here.
async fn write_tcp_answer(writer: &TcpWriter, query: &[u8], response: &[u8]) {
    if writer.broken.is_cancelled() {
        return;
    }
    let response = tcp_answer(query, response);
    // DNS-over-TCP framing must be written completely; write_vectored may be
    // partial, so use write_all_vectored: scatter-gather single syscall with
    // no frame allocation (write_all would copy prefix+body into a new Vec).
    //
    // 长度前缀 + 包体用 write_all_vectored 保证完整写入，保持单 syscall 零分配；
    // write_all 需要拼帧（一次堆分配 + 拷贝）。
    let len_bytes = (response.len() as u16).to_be_bytes();
    let mut bufs = [
        std::io::IoSlice::new(&len_bytes),
        std::io::IoSlice::new(&response),
    ];
    let mut half = writer.half.lock().await;
    let written = tokio::time::timeout(
        TCP_READ_TIMEOUT,
        tokio_util::io::write_all_vectored(&mut *half, &mut bufs),
    )
    .await;
    if !matches!(written, Ok(Ok(()))) {
        writer.shut(&mut half).await;
    }
}
