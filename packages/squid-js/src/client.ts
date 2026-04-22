import initWasm, { Session } from "../wasm/squid_wasm.js";

let initPromise: Promise<void> | null = null;

type Pending = Map<number, { resolve: (v: unknown) => void; reject: (e: Error) => void }>;

function rpc(
  worker: Worker,
  pending: Pending,
  id: number,
  msg: object,
  transfer?: Transferable[],
): Promise<unknown> {
  return new Promise((resolve, reject) => {
    pending.set(id, { resolve, reject });
    worker.postMessage({ ...msg, id }, transfer ?? []);
  });
}

/** Main-thread wasm init; no-op when a Worker is used (wasm loads in the worker). */
export function init(wasmUrl?: string | URL | Request): Promise<void> {
  if (typeof Worker !== "undefined") return Promise.resolve();
  return (initPromise ??= initWasm(wasmUrl ? { module_or_path: wasmUrl } : undefined).then(() => {}));
}

export interface CreateOptions {
  seeds?: Uint8Array;
  paramsSet: string;
  wasmUrl?: string | URL | Request;
}

/** Browser: wasm + `Session` in a worker so crypto does not block the UI. No Worker: main thread after {@link init}. */
export class PoulpyClient {
  readonly evaluationKey: Uint8Array;
  private readonly session: Session | null;
  private readonly worker: Worker | null;
  private nextId = 1;
  private readonly pending: Pending;

  private constructor(ek: Uint8Array, session: Session | null, worker: Worker | null, pending: Pending) {
    this.evaluationKey = ek;
    this.session = session;
    this.worker = worker;
    this.pending = pending;
  }

  static async create(opts: CreateOptions): Promise<PoulpyClient> {
    if (typeof Worker !== "undefined") return PoulpyClient.#workerCreate(opts);
    await init(opts.wasmUrl);
    const { paramsSet } = opts;
    const session = opts.seeds ? Session.fromSeeds(opts.seeds, paramsSet) : Session.newRandom(paramsSet);
    return new PoulpyClient(session.evaluationKeyBytes(), session, null, new Map());
  }

  static async #workerCreate(opts: CreateOptions): Promise<PoulpyClient> {
    const worker = new Worker(new URL("./squid-worker.js", import.meta.url), { type: "module" });
    const pending: Pending = new Map();
    const fail = (e: Error) => {
      pending.forEach((p) => p.reject(e));
      pending.clear();
    };
    worker.onmessage = (ev) => {
      const d = ev.data as { id: number; ok: boolean; error?: string };
      const p = pending.get(d.id);
      if (!p) return;
      pending.delete(d.id);
      d.ok === false ? p.reject(new Error(d.error ?? "worker error")) : p.resolve(ev.data);
    };
    worker.onmessageerror = () => fail(new Error("squid-js: worker message error"));
    worker.onerror = (e) => fail(new Error(e.message));

    const seeds = opts.seeds?.slice().buffer;
    let res: { evaluationKey?: ArrayBuffer };
    try {
      res = (await rpc(
        worker,
        pending,
        0,
        {
          kind: "create",
          paramsSet: opts.paramsSet,
          seeds,
          wasmUrl: opts.wasmUrl != null ? String(opts.wasmUrl) : undefined,
        },
        seeds ? [seeds] : [],
      )) as { evaluationKey?: ArrayBuffer };
    } catch (e) {
      worker.terminate();
      throw e;
    }
    const ek = res.evaluationKey;
    if (!ek) {
      worker.terminate();
      throw new Error("squid-js: worker create missing evaluationKey");
    }
    return new PoulpyClient(new Uint8Array(ek), null, worker, pending);
  }

  #rpc<T>(msg: object, transfer?: Transferable[]): Promise<T> {
    const w = this.worker;
    if (!w) return Promise.reject(new Error("squid-js: no worker"));
    return rpc(w, this.pending, this.nextId++, msg, transfer) as Promise<T>;
  }

  encryptU32(value: number): Promise<Uint8Array> {
    if (!Number.isInteger(value) || value < 0 || value > 0xff_ff_ff_ff) {
      return Promise.reject(new RangeError(`encryptU32: ${value} is out of u32 range`));
    }
    const s = this.session;
    if (s) return Promise.resolve(s.encryptU32(value));
    return this.#rpc<{ ciphertext: ArrayBuffer }>({ kind: "encrypt", value }).then(
      (r) => new Uint8Array(r.ciphertext),
    );
  }

  decryptU32(ciphertext: Uint8Array): Promise<number> {
    const s = this.session;
    if (s) return Promise.resolve(s.decryptU32(ciphertext));
    const ct = ciphertext.slice();
    return this.#rpc<{ value: number }>({ kind: "decrypt", ciphertext: ct.buffer }, [ct.buffer]).then(
      (r) => r.value,
    );
  }

  exportSeeds(): Promise<Uint8Array> {
    const s = this.session;
    if (s) return Promise.resolve(s.seeds());
    return this.#rpc<{ seeds: ArrayBuffer }>({ kind: "exportSeeds" }).then((r) => new Uint8Array(r.seeds));
  }
}

export { Session };
