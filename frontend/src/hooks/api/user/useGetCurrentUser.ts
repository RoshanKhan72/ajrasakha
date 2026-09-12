import { useQuery } from "@tanstack/react-query";
import { UserService } from "../../services/userService";
import type { IUser } from "@/types";
import { useAuthStore } from "@/stores/auth-store";

const userService = new UserService();

export const useGetCurrentUser = (options?: { enabled?: boolean }) => {
  const authStoreUser = useAuthStore((state) => state.user);

  const { data, isLoading, error, refetch } = useQuery<IUser | null, Error>({
    queryKey: ["user", authStoreUser?.email],
    queryFn: async () => {
      try {
        return await userService.getCurrentUser();
      } catch (err) {
        console.warn("Backend getCurrentUser unavailable, falling back to authStore user", err);
        return null;
      }
    },
    enabled: options?.enabled ?? true,
    retry: 1,
  });

  const fallbackUser: IUser | null = authStoreUser
    ? ({
        _id: authStoreUser.uid,
        email: authStoreUser.email,
        name: authStoreUser.name || authStoreUser.email.split("@")[0],
        role: "admin",
        isBlocked: false,
        status: "active",
      } as IUser)
    : null;

  const effectiveUser = data || fallbackUser;

  return {
    data: effectiveUser,
    isLoading: isLoading && !effectiveUser,
    error,
    refetch,
  };
};
