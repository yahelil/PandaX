import type { AdapterFailure, AdapterOperation, AdapterStatus, DataAdapter, DemoListener } from "./adapter";
import { FixtureAdapter } from "./fixtureAdapter";
import { createPortfolioApi, PortfolioApiError, type PortfolioApi } from "./portfolioApi";
import type {
  AnalysisDraft,
  AnalysisJob,
  AnalysisPreview,
  AppSettings,
  Approval,
  CreateProductInput,
  CreateReleaseInput,
  DemoState,
  DocumentRecord,
  EntityId,
  Finding,
  FindingDecisionInput,
  Product,
  Release,
  RemediationInput,
} from "./types";

export type BearerTokenProvider = () => string | undefined | Promise<string | undefined>;

declare global {
  interface Window {
    __ACTIS_GET_BEARER_TOKEN__?: BearerTokenProvider;
  }
}

export interface ProductionAdapterConfig {
  organizationId: string;
  portfolioApi: PortfolioApi;
  fixtureAdapter?: FixtureAdapter;
}

export interface RuntimePortfolioConfig {
  apiUrl?: string;
  organizationId?: string;
  getBearerToken?: BearerTokenProvider;
  fetch?: typeof globalThis.fetch;
}

function today(): string {
  return new Date().toISOString().slice(0, 10);
}

function failure(operation: AdapterOperation, error: unknown): AdapterFailure {
  if (error instanceof PortfolioApiError) {
    return {
      operation,
      code: error.code,
      message: error.message,
      status: error.status,
      occurredAt: new Date().toISOString(),
    };
  }
  return {
    operation,
    code: "unexpected",
    message: error instanceof Error ? error.message : "Unexpected portfolio error",
    occurredAt: new Date().toISOString(),
  };
}

export class ProductionAdapter implements DataAdapter {
  private readonly fixture: FixtureAdapter;
  private readonly dataListeners = new Set<DemoListener>();
  private readonly statusListeners = new Set<DemoListener>();
  private status: AdapterStatus = { mode: "production", phase: "loading" };
  private refreshRevision = 0;

  constructor(private readonly config: ProductionAdapterConfig) {
    this.fixture = config.fixtureAdapter ?? new FixtureAdapter(undefined, false);
    this.fixture.subscribe(() => this.dataListeners.forEach((listener) => listener()));
  }

  getSnapshot = (): DemoState => this.fixture.getSnapshot();
  getStatusSnapshot = (): AdapterStatus => this.status;
  subscribe = (listener: DemoListener): (() => void) => {
    this.dataListeners.add(listener);
    return () => this.dataListeners.delete(listener);
  };
  subscribeStatus = (listener: DemoListener): (() => void) => {
    this.statusListeners.add(listener);
    return () => this.statusListeners.delete(listener);
  };

  initialize = async (options?: { signal?: AbortSignal }): Promise<void> => this.loadPortfolio("initialize", options);
  refresh = async (options?: { signal?: AbortSignal }): Promise<void> => this.loadPortfolio("refresh", options);

  reset = (): void => {
    this.fixture.reset();
    void this.refresh();
  };

  updateSettings = <K extends keyof AppSettings>(section: K, patch: Partial<AppSettings[K]>): void => this.fixture.updateSettings(section, patch);
  acknowledgeNotification = (notificationId: EntityId): void => this.fixture.acknowledgeNotification(notificationId);
  assignFinding = (findingId: EntityId, memberId?: EntityId): Finding => this.fixture.assignFinding(findingId, memberId);
  recordFindingDecision = (input: FindingDecisionInput): Finding => this.fixture.recordFindingDecision(input);
  updateRemediation = (input: RemediationInput): Finding => this.fixture.updateRemediation(input);
  approveDocument = (documentId: EntityId, comment?: string): DocumentRecord => this.fixture.approveDocument(documentId, comment);
  rejectDocument = (documentId: EntityId, comment: string): DocumentRecord => this.fixture.rejectDocument(documentId, comment);
  previewAnalysis = (draft: AnalysisDraft): Promise<AnalysisPreview> => this.fixture.previewAnalysis(draft);
  runAnalysis = (draft: AnalysisDraft): Promise<AnalysisJob> => this.fixture.runAnalysis(draft);
  getAnalysisJob = (jobId: EntityId): AnalysisJob | undefined => this.fixture.getAnalysisJob(jobId);
  getApproval = (documentId: EntityId): Approval | undefined => this.fixture.getApproval(documentId);

  createProduct = async (input: CreateProductInput): Promise<Product> => {
    this.setStatus({ mode: "production", phase: "loading", lastSyncedAt: this.status.lastSyncedAt });
    try {
      const created = await this.config.portfolioApi.createProduct(this.config.organizationId, {
        name: input.name,
        identifier: input.identifier,
        manufacturer: input.manufacturer,
        description: input.description,
        craClass: input.craClass,
        classificationStatus: input.classificationStatus,
        supportStart: today(),
        supportEnd: input.supportUntil,
        ownerId: input.ownerId,
      });
      this.fixture.upsertProduct(created);
      this.markReady();
      return created;
    } catch (error) {
      this.markFailed("create_product", error);
      throw error;
    }
  };

  createRelease = async (input: CreateReleaseInput): Promise<Release> => {
    this.setStatus({ mode: "production", phase: "loading", lastSyncedAt: this.status.lastSyncedAt });
    try {
      const created = await this.config.portfolioApi.createRelease(this.config.organizationId, input.productId, {
        version: input.version,
        channel: input.channel,
        status: "draft",
        releaseDate: input.releaseDate,
        supportStart: input.releaseDate,
        supportEnd: input.supportedUntil,
      });
      this.fixture.upsertRelease(created);
      this.markReady();
      return created;
    } catch (error) {
      this.markFailed("create_release", error);
      throw error;
    }
  };

  private async loadPortfolio(operation: "initialize" | "refresh", options?: { signal?: AbortSignal }): Promise<void> {
    const revision = ++this.refreshRevision;
    this.setStatus({ mode: "production", phase: "loading", lastSyncedAt: this.status.lastSyncedAt });
    try {
      const [organization, products] = await Promise.all([
        this.config.portfolioApi.getOrganization(this.config.organizationId, options),
        this.config.portfolioApi.listProducts(this.config.organizationId, options),
      ]);
      const releases = (await Promise.all(products.map((product) =>
        this.config.portfolioApi.listReleases(this.config.organizationId, product.id, options),
      ))).flat();
      if (revision !== this.refreshRevision) return;
      this.fixture.replacePortfolio(organization, products, releases);
      this.markReady();
    } catch (error) {
      if (revision === this.refreshRevision) this.markFailed(operation, error);
    }
  }

  private markReady(): void {
    this.setStatus({ mode: "production", phase: "ready", lastSyncedAt: new Date().toISOString() });
  }

  private markFailed(operation: AdapterOperation, error: unknown): void {
    this.setStatus({
      mode: "production",
      phase: "error",
      lastSyncedAt: this.status.lastSyncedAt,
      failure: failure(operation, error),
    });
  }

  private setStatus(status: AdapterStatus): void {
    this.status = status;
    this.statusListeners.forEach((listener) => listener());
  }
}

export function createRuntimeDataAdapter(config: RuntimePortfolioConfig): DataAdapter {
  if (!config.apiUrl || !config.organizationId || !config.getBearerToken) return new FixtureAdapter();
  return new ProductionAdapter({
    organizationId: config.organizationId,
    portfolioApi: createPortfolioApi({
      baseUrl: config.apiUrl,
      getBearerToken: config.getBearerToken,
      fetch: config.fetch,
    }),
  });
}
