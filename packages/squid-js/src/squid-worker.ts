import initWasm, { Session } from "../wasm/squid_wasm.js";

const send = (msg: object, transfer?: Transferable[]) =>
  (self as unknown as { postMessage: (m: object, t?: Transferable[]) => void }).postMessage(
    msg,
    transfer,
  );

let wasmReady = false;
let session: Session | null = null;

async function ensureWasm(url?: string) {
  if (!wasmReady) {
    await initWasm(url ? { module_or_path: url } : undefined);
    wasmReady = true;
  }
}

self.onmessage = async (ev: MessageEvent<Record<string, unknown>>) => {
  const d = ev.data;
  const id = d.id as number;
  const kind = d.kind as string;
  try {
    if (kind === "create") {
      await ensureWasm(d.wasmUrl as string | undefined);
      session?.free();
      session = d.seeds
        ? Session.fromSeeds(new Uint8Array(d.seeds as ArrayBuffer), d.paramsSet as string)
        : Session.newRandom(d.paramsSet as string);
      const u = new Uint8Array(session.evaluationKeyBytes());
      send({ id, ok: true, evaluationKey: u.buffer }, [u.buffer]);
      return;
    }
    if (!session) throw new Error("squid-worker: no session");
    if (kind === "encrypt") {
      const u = new Uint8Array(session.encryptU32(d.value as number));
      send({ id, ok: true, ciphertext: u.buffer }, [u.buffer]);
    } else if (kind === "decrypt") {
      const v = session.decryptU32(new Uint8Array(d.ciphertext as ArrayBuffer));
      send({ id, ok: true, value: v });
    } else if (kind === "exportSeeds") {
      const u = new Uint8Array(session.seeds());
      send({ id, ok: true, seeds: u.buffer }, [u.buffer]);
    } else {
      throw new Error(`squid-worker: unknown kind ${kind}`);
    }
  } catch (err) {
    send({
      id,
      ok: false,
      error: err instanceof Error ? err.message : String(err),
    });
  }
};
