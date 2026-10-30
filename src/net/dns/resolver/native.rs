//! Explicitly owned DNS queries on the native UDP/TCP reactor.

use super::*;
use crate::cx::{CancelWakerToken, Cx, cap::CapMask};
use crate::io::{AsyncReadExt, AsyncWriteExt};
use crate::net::UdpSocket;
use crate::time::TimerDriverHandle;
use std::future::poll_fn;

const MAX_UNRELATED_REPLIES: usize = 32;
const MAX_DNS_PACKET: usize = u16::MAX as usize;

impl Resolver {
    /// Resolve A and AAAA records using runtime-owned UDP/TCP sockets.
    ///
    /// This opt-in path requires explicit [`ResolverConfig::nameservers`]
    /// for network queries. It does not invoke NSS, read `/etc/resolv.conf`,
    /// apply search domains, or consult the hosts file. [`Self::lookup_ip`]
    /// retains those system-resolver semantics. Literal addresses and `.invalid`
    /// use the same local handling as `lookup_ip`.
    ///
    /// Both address families progress concurrently within one absolute timeout.
    /// A truncated UDP response is retried over TCP within its remaining attempt
    /// budget. Results use this resolver's existing positive/negative IP cache;
    /// a partial family failure has TTL zero and cannot hide the missing family
    /// in that cache. Record-specific native methods do not cache, matching
    /// their existing counterparts.
    ///
    /// `cx` must retain native I/O authority. Every polling task must also permit
    /// I/O; the explicit owner, original polling task, and subsequent polling
    /// task can cancel the operation or shorten its deadline. Socket polling,
    /// entropy callbacks, and destruction run under the explicit owner. Dropping
    /// this future immediately closes its sockets and removes timer/cancellation
    /// registrations; there is no blocking resolver worker or background task.
    pub async fn lookup_ip_native(&self, cx: &Cx, host: &str) -> Result<LookupIp, DnsError> {
        let mut owner = NativeOwner::new(cx, self.config.timeout);
        let query_deadline = owner.query_deadline();
        owner
            .run(async {
                if let Some(ip) = parse_ip_literal(host) {
                    return Ok(LookupIp::new(vec![ip], Duration::ZERO));
                }
                validate_lookup_hostname(host)?;
                if is_invalid_special_use_domain(host) {
                    return Err(DnsError::NoRecords(host.to_owned()));
                }
                if self.config.cache_enabled {
                    if let Some(cached) = self.cache.get_ip_result(host) {
                        return cached;
                    }
                }
                let nameservers = self.native_nameservers()?;
                let (v6, v4) = futures_lite::future::zip(
                    self.query_records_native(cx, host, DnsQueryType::Aaaa, &nameservers, &query_deadline),
                    self.query_records_native(cx, host, DnsQueryType::A, &nameservers, &query_deadline),
                )
                .await;
                let result = merge_ip_records(host, v6, v4);
                if self.config.cache_enabled {
                    match &result {
                        Ok(lookup) => self.cache.put_ip(host, lookup),
                        Err(DnsError::NoRecords(_)) => self.cache.put_negative_ip_no_records(host),
                        Err(_) => {}
                    }
                }
                result
            })
            .await
    }

    /// Look up MX records on native sockets with the ownership and nameserver
    /// rules of [`Self::lookup_ip_native`]. This does not use the blocking pool.
    pub async fn lookup_mx_native(&self, cx: &Cx, domain: &str) -> Result<LookupMx, DnsError> {
        let answers = self.native_records(cx, domain, DnsQueryType::Mx).await?;
        let records = answers.into_iter().filter_map(|answer| match answer.data {
            DnsRecordData::Mx { preference, exchange } => {
                Some(crate::net::dns::MxRecord { preference, exchange })
            }
            _ => None,
        }).collect();
        Ok(LookupMx::new(records))
    }

    /// Look up SRV records on native sockets with the ownership and nameserver
    /// rules of [`Self::lookup_ip_native`]. Service names may contain underscores.
    pub async fn lookup_srv_native(&self, cx: &Cx, name: &str) -> Result<LookupSrv, DnsError> {
        let answers = self.native_records(cx, name, DnsQueryType::Srv).await?;
        let records = answers.into_iter().filter_map(|answer| match answer.data {
            DnsRecordData::Srv { priority, weight, port, target } => {
                Some(crate::net::dns::SrvRecord { priority, weight, port, target })
            }
            _ => None,
        }).collect();
        Ok(LookupSrv::new(records))
    }

    /// Look up TXT records on native sockets with the ownership and nameserver
    /// rules of [`Self::lookup_ip_native`].
    pub async fn lookup_txt_native(&self, cx: &Cx, name: &str) -> Result<LookupTxt, DnsError> {
        let answers = self.native_records(cx, name, DnsQueryType::Txt).await?;
        let records = answers.into_iter().filter_map(|answer| match answer.data {
            DnsRecordData::Txt(text) => Some(text),
            _ => None,
        }).collect();
        Ok(LookupTxt::new(records))
    }

    fn native_nameservers(&self) -> Result<Vec<SocketAddr>, DnsError> {
        if self.config.nameservers.is_empty() {
            return Err(DnsError::Io(
                "native DNS requires explicit ResolverConfig::nameservers; use lookup_ip for system NSS resolution".into(),
            ));
        }
        validate_configured_nameservers(&self.config.nameservers)
    }

    async fn native_records(
        &self,
        cx: &Cx,
        name: &str,
        kind: DnsQueryType,
    ) -> Result<Vec<DnsAnswer>, DnsError> {
        let mut owner = NativeOwner::new(cx, self.config.timeout);
        let deadline = owner.query_deadline();
        owner.run(async {
            validate_dns_record_name(name)?;
            if is_invalid_special_use_domain(name) {
                return Err(DnsError::NoRecords(name.to_owned()));
            }
            let nameservers = self.native_nameservers()?;
            self.query_records_native(cx, name, kind, &nameservers, &deadline).await
        }).await
    }

    async fn query_records_native(
        &self,
        cx: &Cx,
        name: &str,
        kind: DnsQueryType,
        nameservers: &[SocketAddr],
        deadline: &NativeDeadline,
    ) -> Result<Vec<DnsAnswer>, DnsError> {
        let mut current = name.to_owned();
        let mut alias_ttl: Option<Duration> = None;
        for depth in 0..=8 {
            let mut last_error = None;
            let mut no_records = false;
            let mut alias = None;
            let mut answered = vec![false; nameservers.len()];
            for attempt in 0..=self.config.retries {
                for (index, nameserver) in nameservers.iter().copied().enumerate() {
                    if answered[index] {
                        continue;
                    }
                    cx.checkpoint().map_err(|_| DnsError::Cancelled)?;
                    let remaining = deadline.remaining();
                    if remaining.is_zero() {
                        return Err(DnsError::Timeout);
                    }
                    let unanswered = answered.iter().filter(|done| !**done).count();
                    let left_in_pass = answered[index..].iter().filter(|done| !**done).count();
                    let queries_left = left_in_pass.saturating_add(
                        ((self.config.retries - attempt) as usize).saturating_mul(unanswered),
                    );
                    let allowance = per_attempt_timeout(remaining, queries_left).min(remaining);
                    let attempt_deadline = deadline.shorten(allowance);
                    let id = dns_query_id(self.entropy.as_ref());
                    let query = build_dns_query(&current, kind, id)?;
                    cx.checkpoint().map_err(|_| DnsError::Cancelled)?;
                    let response = attempt_deadline
                        .run(query_nameserver_native(nameserver, &query, id))
                        .await;
                    match response {
                        Ok(response) => match response.rcode {
                            0 => match select_records_for_query(&current, kind, &response.answers) {
                                QuerySelection::Records(mut records) => {
                                    if let Some(ttl) = alias_ttl {
                                        for record in &mut records {
                                            record.ttl = record.ttl.min(ttl);
                                        }
                                    }
                                    return Ok(records);
                                }
                                QuerySelection::Alias(target) => {
                                    if alias.is_none() {
                                        let ttl = response.answers.iter().filter(|answer| {
                                            canonical_dns_name(&answer.name) == canonical_dns_name(&current)
                                                && matches!(&answer.data, DnsRecordData::Cname(found) if found == &target)
                                        }).map(|answer| answer.ttl).min().unwrap_or(Duration::ZERO);
                                        alias = Some((target, ttl));
                                    }
                                    answered[index] = true;
                                }
                                QuerySelection::NoRecords => {
                                    no_records = true;
                                    answered[index] = true;
                                }
                            },
                            3 => {
                                no_records = true;
                                answered[index] = true;
                            }
                            rcode => last_error = Some(DnsError::ServerError(format!(
                                "DNS server returned rcode {rcode} for {current}",
                            ))),
                        },
                        Err(DnsError::Cancelled) => return Err(DnsError::Cancelled),
                        Err(error) => last_error = Some(error),
                    }
                    // Even a synchronously ready peer or many configured retry
                    // attempts cannot monopolize an executor poll or hide a
                    // cancellation arriving during an entropy callback.
                    crate::runtime::yield_now().await;
                }
                if answered.iter().all(|done| *done) {
                    break;
                }
            }
            if let Some((target, ttl)) = alias {
                if depth == 8 {
                    return Err(DnsError::ServerError("DNS CNAME chain exceeded recursion limit".into()));
                }
                current = target;
                alias_ttl = Some(alias_ttl.map_or(ttl, |previous| previous.min(ttl)));
            } else if no_records {
                return Err(DnsError::NoRecords(name.to_owned()));
            } else {
                return Err(last_error.unwrap_or(DnsError::Timeout));
            }
        }
        unreachable!("the bounded CNAME loop returns at its last depth")
    }
}

fn merge_ip_records(
    host: &str,
    v6: Result<Vec<DnsAnswer>, DnsError>,
    v4: Result<Vec<DnsAnswer>, DnsError>,
) -> Result<LookupIp, DnsError> {
    let mut addresses = Vec::new();
    let mut ttl: Option<Duration> = None;
    let mut failure = None;
    for result in [v6, v4] {
        match result {
            Ok(records) => for record in records {
                ttl = Some(ttl.map_or(record.ttl, |previous| previous.min(record.ttl)));
                let address = match record.data {
                    DnsRecordData::A(ip) => IpAddr::V4(ip),
                    DnsRecordData::Aaaa(ip) => IpAddr::V6(ip),
                    _ => continue,
                };
                if !addresses.contains(&address) {
                    addresses.push(address);
                }
            },
            Err(DnsError::NoRecords(_)) => {},
            Err(DnsError::Cancelled) => return Err(DnsError::Cancelled),
            Err(error) => failure = Some(error),
        }
    }
    if addresses.is_empty() {
        Err(failure.unwrap_or_else(|| DnsError::NoRecords(host.to_owned())))
    } else {
        Ok(LookupIp::new(addresses, if failure.is_some() {
            Duration::ZERO
        } else {
            ttl.unwrap_or(Duration::ZERO)
        }))
    }
}

#[derive(Clone)]
struct NativeDeadline {
    clock: Option<TimerDriverHandle>,
    at: Time,
}

impl NativeDeadline {
    fn now(&self) -> Time {
        self.clock.as_ref().map_or_else(crate::time::wall_now, |clock| clock.now())
    }

    fn remaining(&self) -> Duration {
        Duration::from_nanos(self.at.as_nanos().saturating_sub(self.now().as_nanos()))
    }

    fn shorten(&self, allowance: Duration) -> Self {
        Self { clock: self.clock.clone(), at: self.at.min(self.now() + allowance) }
    }

    fn sleep(&self) -> Sleep {
        self.clock.as_ref().map_or_else(
            || Sleep::new(self.at),
            |clock| Sleep::with_timer_driver(self.at, clock.clone()),
        )
    }

    async fn run<T>(&self, future: impl Future<Output = Result<T, DnsError>>) -> Result<T, DnsError> {
        let mut future = std::pin::pin!(future);
        let mut timer = self.sleep();
        poll_fn(|task| {
            if self.now() >= self.at || Pin::new(&mut timer).poll_deadline(task).is_ready() {
                return Poll::Ready(Err(DnsError::Timeout));
            }
            future.as_mut().poll(task)
        }).await
    }
}

struct Cancellation {
    cx: Cx,
    token: Option<CancelWakerToken>,
}

impl Cancellation {
    fn new(cx: Cx) -> Self { Self { cx, token: None } }

    fn register(&mut self, task: &Context<'_>) {
        self.token = Some(self.cx.refresh_cancel_waker(self.token, task.waker()));
    }
}

impl Drop for Cancellation {
    fn drop(&mut self) {
        if let Some(token) = self.token.take() {
            self.cx.clear_cancel_waker(token);
        }
    }
}

struct NativeOwner {
    owner: Cancellation,
    ambient: Option<Cancellation>,
    poller: Option<Cancellation>,
    deadline: NativeDeadline,
    timer: Sleep,
}

impl NativeOwner {
    fn new(cx: &Cx, timeout: Duration) -> Self {
        let clock = cx.timer_driver();
        let now = clock.as_ref().map_or_else(crate::time::wall_now, |clock| clock.now());
        let ambient = Cx::current().map(Cancellation::new);
        let mut deadline = NativeDeadline { clock, at: now + timeout };
        for context in std::iter::once(cx).chain(ambient.as_ref().map(|guard| &guard.cx)) {
            meet_budget(&mut deadline, context);
        }
        let timer = deadline.sleep();
        Self { owner: Cancellation::new(cx.clone()), ambient, poller: None, deadline, timer }
    }

    fn query_deadline(&self) -> NativeDeadline {
        // Leave a bounded margin for joining a successful family with a timed
        // out family and publishing a TTL-zero partial result. The explicit
        // owner deadline still bounds the entire operation.
        self.deadline.shorten(query_budget(self.deadline.remaining()))
    }

    fn check(&mut self, task: &mut Context<'_>) -> Result<(), DnsError> {
        require_native_io(&self.owner.cx, true)?;
        let current = Cx::current();
        if let Some(current) = &current {
            require_native_io(current, false)?;
        }
        if let Some(current) = current.filter(|current| {
            !Arc::ptr_eq(&current.inner, &self.owner.cx.inner)
                && !self.ambient.as_ref().is_some_and(|guard| Arc::ptr_eq(&current.inner, &guard.cx.inner))
        }) {
            if self.poller.as_ref().is_none_or(|guard| !Arc::ptr_eq(&current.inner, &guard.cx.inner)) {
                self.poller = Some(Cancellation::new(current));
            }
        } else {
            self.poller = None;
        }
        self.owner.register(task);
        if let Some(ambient) = &mut self.ambient { ambient.register(task); }
        if let Some(poller) = &mut self.poller { poller.register(task); }
        let old_deadline = self.deadline.at;
        for guard in std::iter::once(&self.owner).chain(self.ambient.iter()).chain(self.poller.iter()) {
            meet_budget(&mut self.deadline, &guard.cx);
        }
        if self.deadline.at < old_deadline {
            self.timer.reset(self.deadline.at);
        }
        if self.deadline.now() >= self.deadline.at {
            return Err(DnsError::Timeout);
        }
        for guard in std::iter::once(&self.owner).chain(self.ambient.iter()).chain(self.poller.iter()) {
            guard.cx.checkpoint().map_err(|_| DnsError::Cancelled)?;
        }
        // A driverless owner's clock must never adopt a later poller's driver.
        let _ambient = self.owner.cx.clone().set_current_restricted();
        if Pin::new(&mut self.timer).poll_deadline(task).is_ready() {
            return Err(DnsError::Timeout);
        }
        Ok(())
    }

    async fn run<T>(&mut self, future: impl Future<Output = Result<T, DnsError>>) -> Result<T, DnsError> {
        let mut future = std::pin::pin!(self.owner.cx.with_ambient(future));
        poll_fn(|task| {
            self.check(task)?;
            future.as_mut().poll(task)
        }).await
    }
}

fn require_native_io(cx: &Cx, require_driver: bool) -> Result<(), DnsError> {
    if !cx.runtime_mask.has(CapMask::IO) || (require_driver && cx.io_driver_handle().is_none()) {
        return Err(DnsError::Io("native DNS requires the owner and polling task to permit I/O, and the owner to retain a native I/O driver".into()));
    }
    Ok(())
}

fn meet_budget(deadline: &mut NativeDeadline, cx: &Cx) {
    if let Some(budget) = cx.budget().deadline {
        let now = cx.timer_driver().as_ref().map_or_else(crate::time::wall_now, |clock| clock.now());
        let remaining = budget.as_nanos().saturating_sub(now.as_nanos());
        deadline.at = deadline.at.min(deadline.now().saturating_add_nanos(remaining));
    }
}

/// A response must echo this query's sole IN question, ID, and standard opcode.
/// Unrelated datagrams are ignored while the original timeout keeps running.
fn matches_query(packet: &[u8], query: &[u8], id: u16) -> bool {
    if packet.len() < 12
        || u16::from_be_bytes([packet[0], packet[1]]) != id
        || u16::from_be_bytes([packet[2], packet[3]]) & 0xf800 != 0x8000
        || u16::from_be_bytes([packet[4], packet[5]]) != 1
    {
        return false;
    }
    let mut offset = 12;
    let Ok(name) = decode_dns_name(packet, &mut offset) else { return false; };
    let Ok(kind) = read_u16(packet, &mut offset) else { return false; };
    let Ok(class) = read_u16(packet, &mut offset) else { return false; };
    class == DnsQueryType::DNS_CLASS_IN
        && first_question(query).is_some_and(|(expected, query_type)| {
            kind == query_type && name.eq_ignore_ascii_case(&expected)
        })
}

async fn query_nameserver_native(
    nameserver: SocketAddr,
    query: &[u8],
    id: u16,
) -> Result<ParsedDnsResponse, DnsError> {
    let response = udp_query(nameserver, query, id).await?;
    if response.truncated {
        tcp_query(nameserver, query, id).await
    } else {
        Ok(response)
    }
}

async fn udp_query(nameserver: SocketAddr, query: &[u8], id: u16) -> Result<ParsedDnsResponse, DnsError> {
    let mut socket = UdpSocket::bind(bind_addr_for(nameserver)).await.map_err(|error| dns_io_error(&error))?;
    socket.connect(nameserver).await.map_err(|error| dns_io_error(&error))?;
    let sent = socket.send(query).await.map_err(|error| dns_io_error(&error))?;
    if sent != query.len() {
        return Err(DnsError::Io("short DNS UDP send".into()));
    }
    let mut packet = vec![0u8; MAX_DNS_PACKET];
    for _ in 0..MAX_UNRELATED_REPLIES {
        let count = socket.recv(&mut packet).await.map_err(|error| dns_io_error(&error))?;
        if matches_query(&packet[..count], query, id) {
            return parse_dns_response(&packet[..count], id, first_question(query).as_ref());
        }
    }
    Err(DnsError::Protocol("too many unrelated DNS UDP responses".into()))
}

async fn tcp_query(nameserver: SocketAddr, query: &[u8], id: u16) -> Result<ParsedDnsResponse, DnsError> {
    let mut stream = TcpStream::connect(nameserver).await.map_err(|error| dns_io_error(&error))?;
    let length = u16::try_from(query.len()).map_err(|_| DnsError::Protocol("DNS query exceeds TCP framing limit".into()))?;
    stream.write_all(&length.to_be_bytes()).await.map_err(|error| dns_io_error(&error))?;
    stream.write_all(query).await.map_err(|error| dns_io_error(&error))?;
    stream.flush().await.map_err(|error| dns_io_error(&error))?;
    for _ in 0..MAX_UNRELATED_REPLIES {
        let mut length = [0u8; 2];
        stream.read_exact(&mut length).await.map_err(|error| dns_io_error(&error))?;
        let mut packet = vec![0u8; usize::from(u16::from_be_bytes(length))];
        stream.read_exact(&mut packet).await.map_err(|error| dns_io_error(&error))?;
        if matches_query(&packet, query, id) {
            let response = parse_dns_response(&packet, id, first_question(query).as_ref())?;
            if response.truncated {
                return Err(DnsError::Protocol("DNS TCP response is truncated".into()));
            }
            return Ok(response);
        }
    }
    Err(DnsError::Protocol("too many unrelated DNS TCP responses".into()))
}

#[cfg(test)]
#[path = "native_tests.rs"]
mod tests;
