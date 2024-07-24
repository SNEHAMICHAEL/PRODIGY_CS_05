import psutil

def list_interfaces():
    interfaces = psutil.net_if_addrs()
    for iface in interfaces:
        print(iface)

if __name__ == "__main__":
    list_interfaces()
