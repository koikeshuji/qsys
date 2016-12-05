import editdistance
from sklearn.covariance import EmpiricalCovariance

from collections import Counter, defaultdict, namedtuple
import ipaddress
import math
import pickle

DEFAULT_RELIABILITY = 0.5
DEFAULT_BLOCK = 0.3
DEFAULT_THRESH = 4.0
DEFAULT_EDIT_THRESH = 64
DEFAULT_CLUSTER_PER = 0.2
ETA = 0.03


def _parse_ip(ip):
    """
    :type ip: str | ipaddress.IPv4Address | ipaddress.IPv6Address
    :rtype: ipaddress.IPv4Address | ipaddress.IPv6Address
    """
    if isinstance(ip, str):
        return ipaddress.ip_address(ip)
    else:
        return ip


def _parse_subnet(subnet):
    """
    :type subnet: str | ipaddress.IPv4Network | ipaddress.IPv6Network
    :rtype: ipaddress.IPv4Network | ipaddress.IPv6Network
    """
    if isinstance(subnet, str):
        return ipaddress.ip_network(subnet)
    else:
        return subnet


def _clamp(x, mini, maxi):
    return max(min(x, maxi), mini)


def freq_byte(payload):
    freq = Counter(payload)
    return [freq[i] for i in range(256)]


QPacket = namedtuple("QPacket", "src_ip dst_ip payload")


class Quarisano(object):
    def __init__(self, subnets=None, thresh=None, block=None):
        """
        :type subnets: list[str]
        """
        if subnets is None:
            subnets = []
        if thresh is None:
            thresh = DEFAULT_THRESH
        if block is None:
            block = DEFAULT_BLOCK

        self.subnets = [_parse_subnet(subnet) for subnet in subnets]
        self.reliability = defaultdict(lambda: DEFAULT_RELIABILITY)
        self.packet_log = defaultdict(list)
        self.payload_log = defaultdict(list)
        self.known_ip = set()
        self.thresh = thresh
        self.block = block

    def register_subnet(self, subnet):
        """
        :type subnet: str
        """
        self.subnets.append(_parse_subnet(subnet))

    def predict(self, packet):
        """
        :type packet: QPacket
        :rtype: bool
        """
        self._update_log(packet)
        src_ip = _parse_ip(packet.src_ip)
        rel = self._update_reliability(src_ip)
        
        if len(self.known_ip) >= 2 and packet.payload:
            cmd_prob = self._get_command_prob(packet)
            self.reliability[src_ip] += (0.3 - cmd_prob) * ETA
            self.reliability[src_ip] = _clamp(self.reliability[src_ip], 0.0, 1.0)

        print("rel:", rel)
        return rel > self.block

    def save(self, f):
        pickle.dump(self, f)

    @staticmethod
    def load(f):
        return pickle.load(f)

    def _update_reliability(self, src_ip):
        src_ip = _parse_ip(src_ip)
        dist = self._get_dist(src_ip)
        delta = -math.tanh((dist - self.thresh / 2)) * ETA
        self.reliability[src_ip] += delta
        self.reliability[src_ip] = _clamp(self.reliability[src_ip], 0.0, 1.0)

        print("dist:{}".format(dist))
        print("delta:{}".format(delta))
        return self.reliability[src_ip]

    def _get_dist(self, src_ip):
        src_ip = _parse_ip(src_ip)
        vec = self._build_vector(src_ip)
        mat = self._build_matrix()
        print(mat)
        mdist = EmpiricalCovariance().fit(mat).mahalanobis([vec])[0]
        return mdist

    def _get_command_prob(packet):
        src_ip = _parse_ip(packet.src_ip)
        eds = {
            ip: [editdistance.eval(packet.payload, x) for x in self.payload_log[ip]]
            for ip in self.known_ip
        }
        near = {
            ip: [x for x in eds[ip] if x < DEFAULT_EDIT_THRESH]
            for ip in self.known_ip
        }
        per = {
            ip: len(near[ip]) / len(eds[ip])
            for ip in self.known_ip
        }
        my = per[src_ip]
        other_avg = sum(per[ip] for ip in self.known_ip if ip != src_ip) / (len(self.known_ip) - 1)
        
        if my > other_avg:
            return (my - other_avg) * (1 - other_avg)
        else:
            return 0.0

    def _build_matrix(self):
        return [
            self._build_vector(ip)
            for ip in self.known_ip
        ]

    def _build_vector(self, ip):
        counter = Counter(self.packet_log[ip])
        features = len(self.subnets)
        return [counter[i] for i in range(-1, features)]

    def _update_log(self, packet):
        src_ip = _parse_ip(packet.src_ip)
        self.packet_log[src_ip].append(self._get_subnet_id(packet.dst_ip))
        if packet.payload:
            self.payload_log[src_ip].append(packet.payload)
        self.known_ip.add(src_ip)

    def _get_subnet_id(self, ip):
        """
        :type ip: str
        :rtype: int
        """
        ip = _parse_ip(ip)
        for idx, subnet in enumerate(self.subnets):
            if ip in subnet:
                return idx
        return -1

_quarisano = Quarisano()
register_subnet = _quarisano.register_subnet
predict = _quarisano.predict
save = _quarisano.save

def load(f):
    global _quarisano
    _quarisano = Quarisano.load(f)
