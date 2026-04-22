import { createRequire } from "node:module";
import type { Evaluator as EvaluatorClass } from "../napi/index.js";

const require = createRequire(import.meta.url);
const addon = require("../napi/index.js") as { Evaluator: typeof EvaluatorClass };

export const Evaluator = addon.Evaluator;
export type Evaluator = EvaluatorClass;
