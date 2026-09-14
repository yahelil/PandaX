import { Link } from "react-router-dom";
import { EmptyState } from "./PageKit";
import "./pages.css";
export function NotFoundPage(){return <main className="page"><section className="panel"><EmptyState title="Page not found" body="The page may have moved, or the current product and release scope may no longer be available." action={<Link className="button button-primary" to="/">Return home</Link>}/></section></main>}
