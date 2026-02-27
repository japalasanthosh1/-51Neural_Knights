import "./style.css";
import { Clerk } from "@clerk/clerk-js";

const app = document.getElementById("app");
const publishableKey = import.meta.env.VITE_CLERK_PUBLISHABLE_KEY;

if (!publishableKey) {
  app.innerHTML = `
    <main class="auth-shell">
      <section class="auth-card">
        <h1>Clerk is not configured</h1>
        <p>Add <code>VITE_CLERK_PUBLISHABLE_KEY</code> in <code>.env</code>.</p>
      </section>
    </main>
  `;
} else {
  const clerk = new Clerk(publishableKey);
  await clerk.load();

  if (clerk.isSignedIn) {
    app.innerHTML = `
      <main class="auth-shell">
        <section class="auth-card signed-in">
          <header class="signed-in-header">
            <h1>Welcome</h1>
            <div id="user-button"></div>
          </header>
          <p>You are signed in.</p>
        </section>
      </main>
    `;

    clerk.mountUserButton(document.getElementById("user-button"));
  } else {
    app.innerHTML = `
      <main class="auth-shell">
        <section class="auth-card">
          <h1>Login</h1>
          <p>Sign in to access the app.</p>
          <div id="sign-in"></div>
        </section>
      </main>
    `;

    clerk.mountSignIn(document.getElementById("sign-in"));
  }
}
