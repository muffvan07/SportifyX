namespace SportifyX.Domain.Helpers
{
    public class Enumerators
    {
        public enum UserRoleEnum : long
        {
            Admin = 1,
            Customer = 2
        }

        public enum VerificationStatusEnum
        {
            Pending = 1,
            Completed = 2
        }

        public enum VerificationTypeEnum
        {
            Email = 1,
            Phone = 2
        }

        public static class UserRoleHelper
        {
            private static readonly Dictionary<UserRoleEnum, bool> RoleStatus = new()
            {
                { UserRoleEnum.Admin, true },
                { UserRoleEnum.Customer, false }
            };

            public static bool IsRoleActive(UserRoleEnum role)
            {
                return RoleStatus.TryGetValue(role, out var isActive) && isActive;
            }

            public static string GetRoleName(long roleId)
            {
                return Enum.IsDefined(typeof(UserRoleEnum), roleId)
                    ? Enum.GetName(typeof(UserRoleEnum), roleId) ?? "Unknown Role"
                    : "Invalid Role";
            }
        }
    }
}
