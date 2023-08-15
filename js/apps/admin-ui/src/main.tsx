import "@patternfly/react-core/dist/styles/base.css";
import "@patternfly/patternfly/patternfly-addons.css";

import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { createHashRouter, RouterProvider } from "react-router-dom";

import { i18n } from "./i18n/i18n";
import { initKeycloak } from "./keycloak";
import { RootRoute } from "./routes";

import "./index.css";

// Initialize required components before rendering app.
await initKeycloak();
await i18n.init();

const router = createHashRouter([RootRoute]);
export const container = document.getElementById("app");
const root = createRoot(container!);

root.render(
  <StrictMode>
    <RouterProvider router={router} />
  </StrictMode>,
);
