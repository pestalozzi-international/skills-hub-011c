import { issuer } from "@openauthjs/openauth";
import { CloudflareStorage } from "@openauthjs/openauth/storage/cloudflare";
import { OidcProvider } from "@openauthjs/openauth/provider/oidc";
import { createSubjects } from "@openauthjs/openauth/subject";
import { object, string } from "valibot";

// Define your subject schema (user)
const subjects = createSubjects({
  user: object({
    id: string(),
  }),
});

export default {
  fetch(request: Request, env: Env, ctx: ExecutionContext) {
    const url = new URL(request.url);

    // Redirect to Logto login
    if (url.pathname === "/") {
      const authUrl = new URL("https://login.pestalozzi.ngo/sign-in");
    
      authUrl.searchParams.set("client_id", "e4el7ulbbndooljneiot2");
      authUrl.searchParams.set("redirect_uri", "https://skillshub.pestalozzi-international.workers.dev/callback");
      authUrl.searchParams.set("response_type", "code");
      authUrl.searchParams.set("scope", "openid profile email");
      authUrl.searchParams.set("prompt", "consent");
      authUrl.searchParams.set("state", crypto.randomUUID());
      authUrl.searchParams.set("interaction_mode", "signIn"); // ✅ try this
    
      return Response.redirect(authUrl.toString());
    }

    // Handle token exchange + session on callback
    if (url.pathname === "/callback") {
      return issuer({
        storage: CloudflareStorage({
          namespace: env.AUTH_STORAGE,
        }),
        subjects,
        providers: {
          oidc: OidcProvider({
            clientID: "e4el7ulbbndooljneiot2",
            clientSecret: "sTo6vVvrYsq81ey9kNFC2QegqCOpC526", // From Logto
            issuer: "https://login.pestalozzi.ngo/oidc",
            scopes: ["openid", "profile", "email"],
          }),
        },
        theme: {
          title: "SkillsHub Login",
          primary: "#0051c3",
          favicon: "https://workers.cloudflare.com/favicon.ico",
          logo: {
            dark: "https://imagedelivery.net/wSMYJvS3Xw-n339CbDyDIA/db1e5c92-d3a6-4ea9-3e72-155844211f00/public",
            light:
              "https://imagedelivery.net/wSMYJvS3Xw-n339CbDyDIA/fa5a3023-7da9-466b-98a7-4ce01ee6c700/public",
          },
        },
        success: async (ctx, value) => {
          // Associate Logto identity with your app’s user system
          return ctx.subject("user", {
            id: await getOrCreateUser(env, value.email),
          });
        },
      }).fetch(request, env, ctx);
    }

    return new Response("Not found", { status: 404 });
  },
} satisfies ExportedHandler<Env>;

// Store or retrieve user record
async function getOrCreateUser(env: Env, email: string): Promise<string> {
  const result = await env.AUTH_DB.prepare(
    `
      INSERT INTO user (email)
      VALUES (?)
      ON CONFLICT (email) DO UPDATE SET email = email
      RETURNING id;
    `
  )
    .bind(email)
    .first<{ id: string }>();

  if (!result) {
    throw new Error(`Unable to process user: ${email}`);
  }

  console.log(`Found or created user ${result.id} with email ${email}`);
  return result.id;
}
