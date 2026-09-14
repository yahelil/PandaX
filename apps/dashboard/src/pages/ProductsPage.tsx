import { type FormEvent, useMemo, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { useDemo } from "../data/DemoProvider";
import type { Product } from "../data/types";
import { PageHeader, StatusPill, formatDate, memberName, relativeDate } from "./PageKit";
import "./pages.css";

type SortKey = "name" | "readiness" | "actions" | "deadline";

export function ProductsPage() {
  const demo = useDemo();
  const navigate = useNavigate();
  const [adding, setAdding] = useState(false);
  const [query, setQuery] = useState("");
  const [readiness, setReadiness] = useState("all");
  const [monitoring, setMonitoring] = useState("all");
  const [sort, setSort] = useState<SortKey>("actions");
  const [createPending, setCreatePending] = useState(false);
  const [createError, setCreateError] = useState<string>();
  const visible = useMemo(() => {
    const lower = query.toLowerCase();
    return demo.products
      .filter((product) => !lower || `${product.name} ${product.identifier} ${product.manufacturer} ${product.tags.join(" ")}`.toLowerCase().includes(lower))
      .filter((product) => readiness === "all" || product.readiness === readiness)
      .filter((product) => monitoring === "all" || product.monitoringHealth === monitoring)
      .sort((a, b) => compareProducts(a, b, sort));
  }, [demo.products, monitoring, query, readiness, sort]);

  return (
    <main className="page">
      <PageHeader
        eyebrow="Portfolio"
        title="Products"
        description="Cybersecurity readiness, monitoring, and regulatory obligations across your portfolio."
        actions={<button className="button button-primary" onClick={() => setAdding((value) => !value)}>Add product</button>}
      />
      {adding ? <CreateProductPanel pending={createPending} error={createError} onCancel={() => setAdding(false)} onCreate={async (input) => {
        setCreatePending(true);
        setCreateError(undefined);
        try {
          const created = await demo.actions.createProduct(input);
          navigate(`/products/${created.id}`);
        } catch (error) {
          setCreateError(error instanceof Error ? error.message : "Product could not be created.");
        } finally {
          setCreatePending(false);
        }
      }} members={demo.state.members} /> : null}
      <section className="panel">
        <div className="toolbar" aria-label="Product filters">
          <input className="search-field" type="search" aria-label="Search products" placeholder="Search products, identifiers, manufacturers…" value={query} onChange={(event) => setQuery(event.target.value)} />
          <select className="select-field" aria-label="Readiness" value={readiness} onChange={(event) => setReadiness(event.target.value)}>
            <option value="all">All readiness</option><option value="ready">Ready</option><option value="needs_attention">Needs attention</option><option value="incomplete_evidence">Incomplete evidence</option>
          </select>
          <select className="select-field" aria-label="Monitoring" value={monitoring} onChange={(event) => setMonitoring(event.target.value)}>
            <option value="all">All monitoring</option><option value="healthy">Healthy</option><option value="degraded">Degraded</option><option value="failed">Failed</option><option value="inactive">Inactive</option>
          </select>
          <select className="select-field" aria-label="Sort products" value={sort} onChange={(event) => setSort(event.target.value as SortKey)}>
            <option value="actions">Most actions</option><option value="deadline">Nearest deadline</option><option value="name">Name</option><option value="readiness">Readiness</option>
          </select>
        </div>
        <div className="data-table-wrap">
          <table className="data-table">
            <thead><tr><th>Product</th><th>Active release</th><th>CRA readiness</th><th>Monitoring</th><th>Actions</th><th>Next deadline</th><th>Owner</th></tr></thead>
            <tbody>{visible.map((product) => {
              const release = demo.selectors.release(product.activeReleaseId);
              return <tr key={product.id}>
                <td><div className="cell-primary"><Link to={`/products/${product.id}`}>{product.name}</Link><small>{product.identifier} · {product.manufacturer}</small></div></td>
                <td><Link to={`/products/${product.id}/releases/${release?.id}`}>{release?.version ?? "No release"}</Link></td>
                <td><StatusPill value={product.readiness} /></td>
                <td><StatusPill value={product.monitoringHealth} /></td>
                <td><strong className={product.actionCount > 2 ? "danger-text" : ""}>{product.actionCount}</strong></td>
                <td><div className="cell-primary"><span className={product.nextDeadline && new Date(product.nextDeadline) < new Date(Date.now() + 3 * 86_400_000) ? "danger-text" : ""}>{relativeDate(product.nextDeadline)}</span><small>{formatDate(product.nextDeadline)}</small></div></td>
                <td>{memberName(demo.state.members, product.ownerId)}</td>
              </tr>;
            })}</tbody>
          </table>
        </div>
        <div className="mobile-card-list">{visible.map((product) => <article className="mobile-card" key={product.id}>
          <div className="cell-primary"><Link to={`/products/${product.id}`}>{product.name}</Link><small>{product.identifier}</small></div>
          <div className="inline-actions"><StatusPill value={product.readiness} /><StatusPill value={product.monitoringHealth} /></div>
          <span>{product.actionCount} open actions · {relativeDate(product.nextDeadline)}</span>
        </article>)}</div>
      </section>
      <p className="muted">Showing {visible.length} of {demo.products.length} products</p>
    </main>
  );
}

function CreateProductPanel({ onCancel, onCreate, members, pending, error }: { onCancel: () => void; onCreate: (input: Parameters<ReturnType<typeof useDemo>["actions"]["createProduct"]>[0]) => Promise<void>; members: ReturnType<typeof useDemo>["state"]["members"]; pending: boolean; error?: string }) {
  const submit = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const data = new FormData(event.currentTarget);
    void onCreate({
      name: String(data.get("name")), identifier: String(data.get("identifier")), manufacturer: String(data.get("manufacturer")),
      description: String(data.get("description")), craClass: String(data.get("craClass")) as "default", classificationStatus: "review_required",
      supportUntil: String(data.get("supportUntil")), ownerId: String(data.get("ownerId")) || undefined,
    });
  };
  return <section className="panel analysis-card"><h2>Add product</h2><p>Start with the product identity and CRA scope. Register the first release next.</p><form className="form-grid" onSubmit={submit}><div className="field"><label htmlFor="product-name">Product name</label><input id="product-name" name="name" className="input-field" required placeholder="Industrial Sensor Gateway" /></div><div className="field"><label htmlFor="product-id">Product identifier</label><input id="product-id" name="identifier" className="input-field" required placeholder="ACM-GTW-620" /></div><div className="field"><label htmlFor="manufacturer">Manufacturer</label><input id="manufacturer" name="manufacturer" className="input-field" required defaultValue="Acme Devices GmbH" /></div><div className="field"><label htmlFor="cra-class">CRA class</label><select id="cra-class" name="craClass" className="select-field"><option value="default">Default</option><option value="important_i">Important class I</option><option value="important_ii">Important class II</option><option value="critical">Critical</option></select></div><div className="field"><label htmlFor="support-until">Support until</label><input id="support-until" name="supportUntil" className="input-field" type="date" required defaultValue="2031-12-31" /></div><div className="field"><label htmlFor="owner">Default owner</label><select id="owner" name="ownerId" className="select-field"><option value="">Unassigned</option>{members.filter((member) => member.status === "active").map((member) => <option key={member.id} value={member.id}>{member.name}</option>)}</select></div><div className="field span-2"><label htmlFor="description">Description</label><textarea id="description" name="description" className="textarea-field" placeholder="Describe the product and its connected functionality." /></div>{error ? <p className="danger-text span-2" role="alert">{error}</p> : null}<div className="inline-actions span-2"><button className="button-primary" type="submit" disabled={pending}>{pending ? "Creating productâ€¦" : "Create product"}</button><button type="button" onClick={onCancel} disabled={pending}>Cancel</button></div></form></section>;
}

function compareProducts(a: Product, b: Product, sort: SortKey) {
  if (sort === "name") return a.name.localeCompare(b.name);
  if (sort === "actions") return b.actionCount - a.actionCount;
  if (sort === "deadline") return (a.nextDeadline ? new Date(a.nextDeadline).getTime() : Infinity) - (b.nextDeadline ? new Date(b.nextDeadline).getTime() : Infinity);
  return ({ needs_attention: 0, incomplete_evidence: 1, ready: 2 }[a.readiness] - { needs_attention: 0, incomplete_evidence: 1, ready: 2 }[b.readiness]);
}
