import { createContext, useContext, useState, type ReactNode } from "react";
import { api, getToken, setToken, type Whoami } from "./api";
import { usePoll } from "./usePoll";

// Session = who is driving the console. With --console-auth OFF the gateway reports anonymous and
// every action is enabled (DEMO default). With auth ON, actions need a pasted operator token and
// sign buttons are limited to the roles the token's principal holds.
export interface Session {
  who: Whoami | null;
  signedIn: boolean;
  signIn: (token: string) => void;
  signOut: () => void;
  ssoLogin: () => void; // redirect to the IdP (OIDC SSO)
  hasRole: (role: string) => boolean;
  refresh: () => void;
}

const Ctx = createContext<Session>({
  who: null,
  signedIn: false,
  signIn: () => {},
  signOut: () => {},
  ssoLogin: () => {},
  hasRole: () => true,
  refresh: () => {},
});

export function SessionProvider({ children }: { children: ReactNode }) {
  const [, bump] = useState(0);
  const { data: who, refresh } = usePoll<Whoami>(
    () => api.whoami().catch(() => ({ authEnabled: true, error: "sign-in required" }) as Whoami),
    15000,
  );
  const session: Session = {
    who,
    signedIn: !!getToken(),
    signIn: (token: string) => {
      setToken(token.trim());
      bump((n) => n + 1);
      refresh();
    },
    signOut: () => {
      // SSO sessions live in a server cookie — hit /auth/logout; token sessions clear the local token
      if (who?.sso && !getToken()) {
        void fetch("/auth/logout", { method: "POST" }).finally(() => window.location.reload());
        return;
      }
      setToken("");
      bump((n) => n + 1);
      refresh();
    },
    ssoLogin: () => {
      window.location.href = "/auth/login";
    },
    // with auth off (or whoami not loaded yet) everything is allowed — the gateway is the authority
    hasRole: (role: string) => !who?.authEnabled || (who?.roles ?? []).includes(role),
    refresh,
  };
  return <Ctx.Provider value={session}>{children}</Ctx.Provider>;
}

export function useSession(): Session {
  return useContext(Ctx);
}
