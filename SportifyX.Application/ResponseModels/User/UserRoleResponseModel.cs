namespace SportifyX.Application.ResponseModels.User
{
    public class UserRoleResponseModel
    {
        public long UserId { get; set; }
        public List<UserRoleItem> UserRoles { get; set; } = new List<UserRoleItem>();
    }

    public class UserRoleItem
    {
        public long RoleId { get; set; }
        public string RoleName { get; set; } = string.Empty;
        public bool IsActive { get; set; }
    }
}
