export default function Footer() {
  return (
    <footer className="border-t border-cyberborder bg-cyberbg py-8 text-center text-sm text-slatelight/50">
      <p className="font-mono">
        <span className="text-neon">$</span> echo &quot;&copy; {new Date().getFullYear()} Hebrides Cyber — Isle of Lewis&quot;
      </p>
      {/* TODO: add links to privacy policy, terms of service, and NDA/MSA templates once drafted. */}
    </footer>
  );
}
