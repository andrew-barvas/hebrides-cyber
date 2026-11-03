import { publishedScannerIps } from "@/lib/scannerEgress";

// The "Where our scans come from" section of /trust. Renders inside the page's
// prose block, so it uses plain elements and inherits that styling.
export default function ScanSourceIps({ ips = publishedScannerIps() }: { ips?: string[] }) {
  return (
    <>
      <h2>Where our scans come from</h2>
      {ips.length > 0 ? (
        <>
          <p>
            Scheduled and on-demand scans come from {ips.length === 1 ? "this fixed address" : "these fixed addresses"}.
            You can allowlist {ips.length === 1 ? "it" : "them"} in your WAF or firewall, or give{" "}
            {ips.length === 1 ? "it" : "them"} to whoever watches your logs so our traffic is recognised.
          </p>
          <ul>
            {ips.map((ip) => (
              <li key={ip}>
                <code>{ip}</code>
              </li>
            ))}
          </ul>
          <p>
            If our main scanners are unavailable, a backup path may scan from GitHub&apos;s shared cloud addresses
            instead. Those are not ours alone, so do not allowlist them.
          </p>
        </>
      ) : (
        <p>
          We are moving our scanners onto a fixed source address that you can allowlist. It is not published yet,
          and we will list it here when it is live. Until then, scans come from GitHub&apos;s shared cloud
          addresses, which change and are not ours alone.
        </p>
      )}
    </>
  );
}
