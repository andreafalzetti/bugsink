import ipaddress
from typing import Union, List


def parse_cidr(cidr_str: str) -> Union[ipaddress.IPv4Network, ipaddress.IPv6Network]:
    """
    Parse a CIDR notation string into an IPv4 or IPv6 network object.
    
    Args:
        cidr_str: String in CIDR notation (e.g., '10.0.0.0/8', '[2001:db8::/32]')
    
    Returns:
        IPv4Network or IPv6Network object
    
    Raises:
        ValueError: If the CIDR notation is invalid
    """
    # Remove brackets if present (for IPv6)
    if cidr_str.startswith('[') and cidr_str.endswith(']'):
        cidr_str = cidr_str[1:-1]
    
    try:
        return ipaddress.ip_network(cidr_str, strict=False)
    except ValueError as e:
        raise ValueError(f"Invalid CIDR notation: {cidr_str}") from e


def is_ip_in_cidr(ip_str: str, cidr_str: str) -> bool:
    """
    Check if an IP address is within a CIDR range.
    
    Args:
        ip_str: IP address as string
        cidr_str: CIDR notation string
    
    Returns:
        True if IP is within CIDR range, False otherwise
    """
    try:
        # Remove brackets from IPv6 addresses if present
        if ip_str.startswith('[') and ip_str.endswith(']'):
            ip_str = ip_str[1:-1]
            
        ip = ipaddress.ip_address(ip_str)
        network = parse_cidr(cidr_str)
        
        # Ensure both are same IP version
        if isinstance(ip, ipaddress.IPv4Address) and isinstance(network, ipaddress.IPv4Network):
            return ip in network
        elif isinstance(ip, ipaddress.IPv6Address) and isinstance(network, ipaddress.IPv6Network):
            return ip in network
        else:
            return False
            
    except (ValueError, ipaddress.AddressValueError):
        return False


def is_host_allowed(host: str, allowed_hosts: List[str]) -> bool:
    """
    Check if a host is allowed based on ALLOWED_HOSTS configuration.
    
    This extends Django's ALLOWED_HOSTS to support CIDR notation.
    
    Args:
        host: The host to check (can be domain name or IP address)
        allowed_hosts: List of allowed hosts (domains, IPs, or CIDR ranges)
    
    Returns:
        True if host is allowed, False otherwise
    """
    # Handle wildcard
    if '*' in allowed_hosts:
        return True
    
    # Direct match (case-insensitive for domains)
    if host.lower() in [h.lower() for h in allowed_hosts]:
        return True
    
    # Check if it's an IP address
    try:
        # Try to parse as IP address
        if host.startswith('[') and host.endswith(']'):
            ip_str = host[1:-1]  # Remove brackets for IPv6
        else:
            ip_str = host
            
        ipaddress.ip_address(ip_str)
        
        # It's a valid IP, check against CIDR ranges
        for allowed in allowed_hosts:
            if '/' in allowed:  # Looks like CIDR notation
                if is_ip_in_cidr(host, allowed):
                    return True
                    
    except (ValueError, ipaddress.AddressValueError):
        # Not an IP address, it's a domain name
        # Check for subdomain wildcards (e.g., '.example.com')
        for allowed in allowed_hosts:
            if allowed.startswith('.') and (
                host.endswith(allowed) or host == allowed[1:]
            ):
                return True
    
    return False