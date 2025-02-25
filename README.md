# TLS_VPN
**Personal solutions for the course project of HUST `Network Security`**

## Getting Started
### 1. Environment Setup
-   **VM:** Ubuntu 16.04
-   **Docker:** to simulate the client (HostU) and an internal network host (HostV).
-   **Dependencies:** `openssl` library
-   **Network Configuration:**
    -   two Docker networks: `extranet` and `intranet`
    -   Launch HostU and HostV containers and connect them to the respective `extranet` and `intranet` networks.
    -   Remove the default routes inside the HostU and HostV containers.

### 2. Certificate Acquisition and Configuration
miniVPN utilizes TLS/SSL for secure communication and employs certificates for server authentication. You will need to generate a CA certificate, a server certificate, and optionally, client certificates.
-   **Generate CA Certificate:** Generate a self-signed Certificate Authority (CA) certificate using the `openssl` tool.
-   **Generate Server Certificate:**
    -   Generate a server private key.
    -   Generate a Certificate Signing Request (CSR) for the server.
    -   Sign the server CSR using the previously generated CA certificate to issue the server certificate.
-   **Generate Client Certificates (Optional):** follow a similar procedure to generate client certificates.

**Notes:**
-   Properly configure the `openssl.cnf` file, including specifying paths for directories like `dir`, `certs`, and `crl_dir`.
-   Do not use the example domain `vpnserver.com` in your code; use your own domain name and include your name in the server certificate's common name.
-   Ensure that the generated certificates and private keys are copied to accessible directories before running the project (check the code).

### 3. Running miniVPN

-   **VPN Server:** Launch the VPN server executable on the designated server machine. Then, configure the `tun0` interface, enable IP forwarding, and clear any existing `iptables` rules.
-   **VPN Client:** Run the VPN client executable on the HostU machine, connecting to the VPN server's IP address. Configure the `tun0` interface on the client-side as well.

### 4. Routing Configuration

-   **HostU:** Add a routing rule on HostU to direct traffic destined for the internal network (e.g., 192.168.60.0/24) to the `tun0` interface.
-   **HostV:** Configure a routing rule on HostV to direct return traffic back to the VPN server. The specific IP address will depend on your setup.
-   **VPN Server (VM):** Make sure IP forwarding is enabled on the VPN server, and any existing `iptables` rules are cleared.

## Troubleshooting
- If vpnclient and vpnserver fail to create a virtual network interface, try running them with superuser privileges.
- If vpnclient and vpnserver cannot connect, check your firewall to make sure it is not blocking the ports used for communication and try running them with superuser privileges.

## Further Information
Refer to the detailed lab manual for guidance and code explanations.
