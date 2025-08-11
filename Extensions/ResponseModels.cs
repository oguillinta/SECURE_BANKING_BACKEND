namespace ApiSecureBank.Extensions
{
    public record UserInfoResponse(
   string? UserId, string? Name, string? Email, string[] Roles,
   IEnumerable<object> Claims, bool IsAuthenticated,
   string? AuthenticationType, DateTime Timestamp
);

    public record AdminDataResponse(string Message, object SystemInfo, object RequestInfo, DateTime Timestamp);
    public record KeyVaultTestResponse(string Message, bool KeyVaultConfigured, string KeyVaultUrl, bool TestSecretExists, string Environment, DateTime Timestamp);
    public record ResilienceTestResponse(string Message, List<object> Results, DateTime Timestamp);
}
