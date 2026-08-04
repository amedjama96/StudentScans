export default function App() {
  return (
    <main className="page">
      <section className="hero">
        <span className="badge">Student project • Day 2</span>
        <h1>StudentScans</h1>
        <p className="lead">
          Check the basic external security posture of a website.
        </p>

        <div className="coming-soon">
          <h2>Coming next</h2>
          <ul>
            <li>Domain input</li>
            <li>Security scan</li>
            <li>Security score</li>
            <li>Recommendations</li>
          </ul>
        </div>

        <button disabled>Scan coming tomorrow</button>
      </section>
    </main>
  );
}
