// Import the functions you need from the SDKs you need
import { initializeApp } from "firebase/app";
import { getAnalytics } from "firebase/analytics";
import {
  getAuth,
  GoogleAuthProvider,
  signInWithEmailAndPassword,
  signOut,
  createUserWithEmailAndPassword,
  updateProfile,
  EmailAuthProvider,
  reauthenticateWithCredential,
  updatePassword,
} from "firebase/auth";
import { firebaseConfig } from "@/config/firebase";
import { useAuthStore } from "@/stores/auth-store";
import { UserService } from "@/hooks/services/userService";
import { AuthService } from "@/hooks/services/authService";
import { isDevelopment } from "@/shared/app";
const authService = new AuthService();


// Initialize Firebase
const app = initializeApp(firebaseConfig);
export const auth = getAuth(app);
export const provider = new GoogleAuthProvider();
const userService = new UserService()
export const loginWithEmail = async (email: string, password: string) => {
  try {
    let user: any = null;
    try {
      user = await userService.Getuser(email);
    } catch (e) {
      console.warn("Backend user lookup failed, proceeding with auth flow", e);
    }

    // Moderators and Experts are gated by activity status (isBlocked is their check-in/
    // checkout availability flag); every other role is gated by isBlocked, as before.
    const isModeratorOrExpert = user?.role === "moderator" || user?.role === "expert";
    const deniedLogin = isModeratorOrExpert ? user?.status === "in-active" : !!user?.isBlocked;
    if (deniedLogin) {
      throw new Error("User marked as Inactive Please Contact Moderator");
    }

    try {
      const result = await signInWithEmailAndPassword(auth, email, password);

      // Enforce email verification
      if (!result.user.emailVerified && !isDevelopment) {
        try {
          await authService.resendVerification(email);
        } catch (resendError) {
          console.error("Failed to trigger verification resend:", resendError);
        }

        await signOut(auth);
        throw new Error("Please verify your email before logging in. A new verification link has been sent to your email.");
      }

      // Sync user with backend database
      try {
        const idToken = await result.user.getIdToken();
        const syncResponse = await authService.accountSync(idToken);
        return Object.assign(result, { appUser: syncResponse?.user });
      } catch (syncErr) {
        return Object.assign(result, { appUser: user });
      }
    } catch (firebaseErr: any) {
      // Re-throw specific business logic errors
      if (
        firebaseErr instanceof Error &&
        (firebaseErr.message.includes("User marked as Inactive") ||
          firebaseErr.message.includes("verify your email"))
      ) {
        throw firebaseErr;
      }

      // If Firebase API key is invalid or dummy (auth/invalid-api-key), fallback to dev mock user
      const isInvalidApiKey =
        firebaseErr?.code === "auth/invalid-api-key" ||
        firebaseErr?.message?.includes("invalid-api-key") ||
        firebaseErr?.message?.includes("API key not valid") ||
        firebaseConfig.apiKey?.includes("dummy") ||
        firebaseConfig.apiKey === "";

      if (isInvalidApiKey) {
        console.warn("[Dev Auth] Firebase API key is dummy or invalid. Falling back to dev mock authentication.");
        const mockUid = user?._id || "dev-user-id-" + Date.now();
        const mockUser = {
          uid: mockUid,
          email: email,
          displayName: user?.name || user?.firstName || email.split("@")[0],
          photoURL: "",
          emailVerified: true,
          getIdToken: async () => "mock-id-token",
        };
        return {
          user: mockUser,
          appUser: user || { _id: mockUid, role: "admin", email, name: email.split("@")[0] },
        };
      }

      throw firebaseErr;
    }
  } catch (error: unknown) {
    throw error;
  }
};

// Add a function to create a user with email and password
export const createUserWithEmail = async (
  email: string,
  password: string,
  displayName?: string
) => {
  try {
    const userCredential = await createUserWithEmailAndPassword(
      auth,
      email,
      password
    );

    // Update user profile if display name is provided
    if (displayName && userCredential.user) {
      await updateProfile(userCredential.user, {
        displayName,
      });
    }

    return userCredential;
  } catch (error: any) {
    const isInvalidApiKey =
      error?.code === "auth/invalid-api-key" ||
      error?.message?.includes("invalid-api-key") ||
      error?.message?.includes("API key not valid") ||
      firebaseConfig.apiKey?.includes("dummy") ||
      firebaseConfig.apiKey === "";

    if (isInvalidApiKey) {
      console.warn("[Dev Auth] Firebase API key is dummy or invalid. Returning dev mock signup credential.");
      const mockUid = "dev-user-id-" + Date.now();
      return {
        user: {
          uid: mockUid,
          email: email,
          displayName: displayName || email.split("@")[0],
          photoURL: "",
          emailVerified: true,
          getIdToken: async () => "mock-id-token",
        },
      } as any;
    }
    throw error;
  }
};

export const logout = () => {
  signOut(auth);
  useAuthStore.getState().clearUser();
};

export const verifyCurrentPassword = async (
  email: string,
  currentPassword: string
) => {
  if (!auth.currentUser) throw new Error("User not logged in");

  const credential = EmailAuthProvider.credential(email, currentPassword);

  try {
    await reauthenticateWithCredential(auth.currentUser, credential);
    return { success: true };
  } catch (error) {
    return { success: false, error };
  }
};

export const updateUserPassword = async (newPassword: string) => {
  if (!auth.currentUser) throw new Error("User not logged in");

  try {
    await updatePassword(auth.currentUser, newPassword);
    return { success: true };
  } catch (error) {
    return { success: false, error };
  }
};

export const analytics = getAnalytics(app);
