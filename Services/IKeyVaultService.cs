namespace ApiSecureBank.Services
{
    public interface IKeyVaultService
    {
        Task<string?> GetSecretAsync(string secretName);
        Task<bool> SetSecretAsync(string secretName, string secretValue);
        Task<bool> DeleteSecretAsync(string secretName);
        Task<Dictionary<string, string>> GetAllSecretsAsync();

       
        Task<string> EncryptDataAsync(string keyName, string plaintext);
        Task<string> DecryptDataAsync(string keyName, string ciphertext);
      
        Task<bool> SecretExistsAsync(string secretName);
        Task<bool> IsConnectedAsync();
        Task<string> GetKeyVaultInfoAsync();
    }
}
