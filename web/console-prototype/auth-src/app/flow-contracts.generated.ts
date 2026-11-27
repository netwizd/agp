// Generated from docs/v2/schemas/identity-flow.schema.json. Do not edit.
export type FlowView = {
  id: string;
  purpose: "login" | "step_up" | "verify_email" | "activate" | "recover";
  audience: "management" | "login" | "setup";
  state: "pending_primary" | "pending_mfa" | "ready" | "completed" | "expired" | "cancelled";
  nextStep: "primary" | "redirect" | "totp" | "email_code" | "complete" | "none" | "totp_enrollment" | "recovery" | "password_setup";
  expiresAt: string;
  mfaSatisfied: boolean;
  contactId?: string;
};

export type StartFlow = {
  purpose: "login" | "step_up" | "verify_email" | "activate" | "recover";
  audience: "management" | "login" | "setup";
};

export type PrimaryProof = {
  method: "local_password";
  username: string;
  password: string;
} | {
  method: "directory_password";
  providerId: string;
  username: string;
  password: string;
} | {
  method: "invitation";
  token: string;
};

export type TotpProof = {
  code: string;
};

export type ChallengeView = {
  id: string;
  flowId: string;
  purpose: "verify_email" | "invite_confirmation" | "recovery_confirmation";
  generation: string;
  expiresAt: string;
  resendAfter: string;
  deliveryState: "queued" | "accepted" | "failed" | "expired";
};

export type EmailIssue = {
  purpose: "verify_email" | "invite_confirmation" | "recovery_confirmation";
  contactId: string;
};

export type EmailProof = {
  code: string;
};
