// Bundled SPA application. The client-side routes below live only in this
// served bundle -- they are not present in the server source or the server's
// HTML responses, so only a crawler that reads the bundle can discover them.
import { createRouter, createWebHistory } from "/static/vendor.js";

const routes = [
  { path: "/dashboard", component: "Dashboard" },
  { path: "/admin/users", component: "AdminUsers" },
  { path: "/settings/profile", component: "Profile" },
];

const router = createRouter({ history: createWebHistory(), routes });

export default router;
