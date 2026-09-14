import { Navigate, Route, Routes } from 'react-router-dom'
import { AppShell } from './components/AppShell'
import {
  AnalysisPage,
  AnalysisResultPage,
  CompliancePage,
  DocumentDetailPage,
  FindingDetailPage,
  FindingsPage,
  HomePage,
  NotFoundPage,
  ProductsPage,
  ProductWorkspacePage,
  ReleaseWorkspacePage,
  SettingsPage,
  ClientDemoPage,
} from './pages'

export function App() {
  return (
    <Routes>
      <Route element={<AppShell />}>
        <Route index element={<HomePage />} />
        <Route path="products" element={<ProductsPage />} />
        <Route path="products/client-demo" element={<ClientDemoPage view="portfolio" />} />
        <Route path="products/client-demo/home-hub" element={<ClientDemoPage view="product" />} />
        <Route path="products/client-demo/upload" element={<ClientDemoPage view="upload" />} />
        <Route path="products/client-demo/alert" element={<ClientDemoPage view="alert" />} />
        <Route path="products/:productId" element={<ProductWorkspacePage />} />
        <Route path="products/:productId/releases/:releaseId" element={<ReleaseWorkspacePage />} />
        <Route path="products/:productId/releases/:releaseId/analyze" element={<AnalysisPage />} />
        <Route path="analyses/:analysisId" element={<AnalysisResultPage />} />
        <Route path="findings" element={<FindingsPage />} />
        <Route path="findings/client-demo" element={<ClientDemoPage view="finding" />} />
        <Route path="findings/:findingId" element={<FindingDetailPage />} />
        <Route path="compliance" element={<CompliancePage />} />
        <Route path="compliance/client-demo" element={<ClientDemoPage view="documents" />} />
        <Route path="documents/:documentId" element={<DocumentDetailPage />} />
        <Route path="settings" element={<Navigate replace to="/settings/organization" />} />
        <Route path="settings/:section" element={<SettingsPage />} />
        <Route path="*" element={<NotFoundPage />} />
      </Route>
    </Routes>
  )
}
