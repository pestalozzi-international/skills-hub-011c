import { issuer } from "@openauthjs/openauth";
import { CloudflareStorage } from "@openauthjs/openauth/storage/cloudflare";
import { OidcProvider } from "@openauthjs/openauth/provider/oidc";
import { createSubjects } from "@openauthjs/openauth/subject";
import { object, string } from "valibot";

// Define your subject schema (user type)
const subjects = createSubjects({
  user: object({
    id: string(),
  }),
});

export default {
  fetch(request: Request, env: Env, ctx: ExecutionContext) {
    const url = new URL(request.url);

    // Initial redirect to start the OIDC login flow
    if (url.pathname === "/") {
      url.searchParams.set("redirect_uri", url.origin + "/callback");
      url.searchParams.set("client_id", "i7jp5dxriy6wglluryopx"); // From your Logto App ID
      url.searchParams.set("response_type", "code");
      url.pathname = "/authorize";
      return Response.redirect(url.toString());
    }

    // Callback endpoint after login
    if (url.pathname === "/callback") {
      return Response.json({
        message: "OIDC flow complete!",
        params: Object.fromEntries(url.searchParams.entries()),
      });
    }

    // OpenAuth issuer handles OIDC login, session, and subject creation
    return issuer({
      storage: CloudflareStorage({
        namespace: env.AUTH_STORAGE,
      }),
      subjects,
      providers: {
        oidc: OidcProvider({
          clientID: "i7jp5dxriy6wglluryopx",
          issuer: "https://login.pestalozzi.ngo/oidc",
	  clientSecret: "CSmMaYjMkfEuejXmzmHvg5UYrGqKd6sL",
          scopes: ["openid", "profile", "email"],
          query: {
            prompt: "consent",
          },
        }),
      },
      theme: {
        title: "myAuth",
        primary: "#0051c3",
        favicon: "https://workers.cloudflare.com//favicon.ico",
        logo: {
          dark: "https://imagedelivery.net/wSMYJvS3Xw-n339CbDyDIA/db1e5c92-d3a6-4ea9-3e72-155844211f00/public",
          light:
            "https://imagedelivery.net/wSMYJvS3Xw-n339CbDyDIA/fa5a3023-7da9-466b-98a7-4ce01ee6c700/public",
        },
      },
      success: async (ctx, value) => {
        return ctx.subject("user", {
          id: await getOrCreateUser(env, value.email),
        });
      },
    }).fetch(request, env, ctx);
  },
} satisfies ExportedHandler<Env>;

// Util to create or retrieve a user in your DB
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
