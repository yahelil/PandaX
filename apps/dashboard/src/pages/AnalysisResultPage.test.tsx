import { renderToStaticMarkup } from "react-dom/server";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { expect, it } from "vitest";
import { DemoProvider } from "../data/DemoProvider";
import { FixtureAdapter } from "../data/fixtureAdapter";
import { createDemoState } from "../data/fixtures";
import { AnalysisResultPage } from "./AnalysisResultPage";

it("shows a failed analysis and its server error instead of claiming it is still running", () => {
  const state = createDemoState();
  const job = state.analysisJobs[0];
  job.status = "failed";
  job.progress = 70;
  job.stage = "S6 DOSSIER";
  job.error = "Dossier not sealed: PDF validation failed";

  const html = renderToStaticMarkup(
    <MemoryRouter initialEntries={[`/analyses/${job.id}`]}>
      <DemoProvider adapter={new FixtureAdapter(state, false)}>
        <Routes><Route path="/analyses/:analysisId" element={<AnalysisResultPage />} /></Routes>
      </DemoProvider>
    </MemoryRouter>,
  );

  expect(html).toContain("Analysis failed");
  expect(html).toContain(job.error);
  expect(html).toContain("Upload and try again");
  expect(html).not.toContain("Analysis in progress");
});
