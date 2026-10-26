import { handle } from './handler.js';
import { D1Store } from './db.js';

export default {
  fetch(request, env) {
    return handle(request, new D1Store(env.DB), env);
  },
};
