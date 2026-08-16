export default function Footer() {
  return (
    <footer className="border-t border-cyberborder bg-cyberbg py-8 text-center text-sm text-slatelight/60">
      <p className="font-mono">
        <span aria-hidden="true" className="text-neon">$</span>{" "}
        &copy; {new Date().getFullYear()} Hebrides Cyber — Isle of Lewis
      </p>
    </footer>
  );
}
