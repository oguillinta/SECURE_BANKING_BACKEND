using Azure.Identity;
using Azure.Security.KeyVault.Secrets;
using Azure.Security.KeyVault.Keys;
using Azure.Security.KeyVault.Keys.Cryptography;
using Azure.Identity;
using Microsoft.AspNetCore.DataProtection.AuthenticatedEncryption;
using System.Collections.Concurrent;
using System.Net;
using System.Text;

namespace ApiSecureBank.Services
{
    public class KeyVaultService : IKeyVaultService
    {
        private readonly SecretClient _secretClient;
        private readonly KeyClient _keyClient;
        private readonly ILogger<KeyVaultService> _logger;
        private readonly ConcurrentDictionary<string, (string Value, DateTime Expiry)> _cache;
        private readonly TimeSpan _cacheExpiry = TimeSpan.FromMinutes(5);

        public KeyVaultService(IConfiguration configuration, KeyClient keyClient, ILogger<KeyVaultService> logger)
        {
            _logger = logger;
            _cache = new ConcurrentDictionary<string, (string, DateTime)>();

            var keyVaultUrl = configuration["KeyVault:VaultUrl"];
            if (string.IsNullOrEmpty(keyVaultUrl))
            {
                throw new InvalidOperationException("KeyVault:VaultUrl no está configurado");
            }
            _keyClient = keyClient;
            var credential = new DefaultAzureCredential();
            _secretClient = new SecretClient(new Uri(keyVaultUrl), credential);

            _logger.LogInformation("KeyVaultService inicializado con URL: {KeyVaultUrl}", keyVaultUrl);
        }

        public async Task<string?> GetSecretAsync(string secretName)
        {
            try
            {
                ArgumentException.ThrowIfNullOrEmpty(secretName);

                // Verificar caché primero
                if (_cache.TryGetValue(secretName, out var cachedValue) && cachedValue.Expiry > DateTime.UtcNow)
                {
                    _logger.LogDebug("Secreto {SecretName} obtenido desde caché", secretName);
                    return cachedValue.Value;
                }

                // Obtener desde Key Vault
                var response = await _secretClient.GetSecretAsync(secretName);
                var secretValue = response.Value.Value;

                // Guardar en caché
                _cache.TryAdd(secretName, (secretValue, DateTime.UtcNow.Add(_cacheExpiry)));

                _logger.LogInformation("Secreto {SecretName} obtenido exitosamente de Key Vault", secretName);
                return secretValue;
            }
            catch (Azure.RequestFailedException ex) when (ex.Status == 404)
            {
                _logger.LogWarning("Secreto {SecretName} no encontrado en Key Vault", secretName);
                return null;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error al obtener el secreto {SecretName} de Key Vault", secretName);
                throw;
            }
        }

        public async Task<bool> SetSecretAsync(string secretName, string secretValue)
        {
            try
            {
                ArgumentException.ThrowIfNullOrEmpty(secretName);
                ArgumentException.ThrowIfNullOrEmpty(secretValue);

                await _secretClient.SetSecretAsync(secretName, secretValue);

                // Actualizar caché
                _cache.AddOrUpdate(secretName,
                    (secretValue, DateTime.UtcNow.Add(_cacheExpiry)),
                    (key, oldValue) => (secretValue, DateTime.UtcNow.Add(_cacheExpiry)));

                _logger.LogInformation("Secreto {SecretName} establecido exitosamente en Key Vault", secretName);
                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error al establecer el secreto {SecretName} en Key Vault", secretName);
                return false;
            }
        }

        public async Task<bool> DeleteSecretAsync(string secretName)
        {
            try
            {
                ArgumentException.ThrowIfNullOrEmpty(secretName);

                var operation = await _secretClient.StartDeleteSecretAsync(secretName);
                await operation.WaitForCompletionAsync();

                // Remover del caché
                _cache.TryRemove(secretName, out _);

                _logger.LogInformation("Secreto {SecretName} eliminado exitosamente de Key Vault", secretName);
                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error al eliminar el secreto {SecretName} de Key Vault", secretName);
                return false;
            }
        }

        public async Task<Dictionary<string, string>> GetAllSecretsAsync()
        {
            try
            {
                var secrets = new Dictionary<string, string>();

                await foreach (var secretProperties in _secretClient.GetPropertiesOfSecretsAsync())
                {
                    if (secretProperties.Enabled == true)
                    {
                        var secret = await GetSecretAsync(secretProperties.Name);
                        if (secret != null)
                        {
                            secrets[secretProperties.Name] = secret;
                        }
                    }
                }

                _logger.LogInformation("Obtenidos {Count} secretos de Key Vault", secrets.Count);
                return secrets;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error al obtener todos los secretos de Key Vault");
                throw;
            }
        }

        
        public async Task<string> EncryptDataAsync(string keyName, string plaintext)
        {
            try
            {
                var key = await _keyClient.GetKeyAsync(keyName);
                var cryptoClient = new CryptographyClient(key.Value.Id, new DefaultAzureCredential());

                var plaintextBytes = Encoding.UTF8.GetBytes(plaintext);
                var encryptResult = await cryptoClient.EncryptAsync(Azure.Security.KeyVault.Keys.Cryptography.EncryptionAlgorithm.RsaOaep, plaintextBytes);

                var encryptedBase64 = Convert.ToBase64String(encryptResult.Ciphertext);
                _logger.LogInformation("Successfully encrypted data using key: {KeyName}", keyName);

                return encryptedBase64;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error encrypting data with key: {KeyName}", keyName);
                throw;
            }
        }

        public async Task<string> DecryptDataAsync(string keyName, string ciphertext)
        {
            try
            {
                var key = await _keyClient.GetKeyAsync(keyName);
                var cryptoClient = new CryptographyClient(key.Value.Id, new DefaultAzureCredential());

                var ciphertextBytes = Convert.FromBase64String(ciphertext);
                var decryptResult = await cryptoClient.DecryptAsync(Azure.Security.KeyVault.Keys.Cryptography.EncryptionAlgorithm.RsaOaep, ciphertextBytes);

                var plaintext = Encoding.UTF8.GetString(decryptResult.Plaintext);
                _logger.LogInformation("Successfully decrypted data using key: {KeyName}", keyName);

                return plaintext;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error decrypting data with key: {KeyName}", keyName);
                throw;
            }
        }

         
        public async Task<bool> SecretExistsAsync(string secretName)
        {
            try
            {
                await _secretClient.GetSecretAsync(secretName);
                return true;
            }
            catch
            {
                return false;
            }
        }

        public async Task<bool> IsConnectedAsync()
        {
            try
            {
                // Intentar listar secretos como test de conectividad
                await foreach (var secret in _secretClient.GetPropertiesOfSecretsAsync())
                {
                    // Solo necesitamos verificar que podemos conectar
                    break;
                }
                return true;
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Key Vault connectivity test failed");
                return false;
            }
        }

        public async Task<string> GetKeyVaultInfoAsync()
        {
            try
            {
                var secretCount = 0;
                await foreach (var secret in _secretClient.GetPropertiesOfSecretsAsync())
                {
                    secretCount++;
                }

                var vaultUri = _secretClient.VaultUri.ToString();
                return $"Key Vault: {vaultUri}, Secrets: {secretCount}";
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting Key Vault info");
                return "Error getting Key Vault info";
            }
        }

        private static string MaskSensitiveValue(string value)
        {
            if (string.IsNullOrEmpty(value) || value.Length <= 8)
                return "***";

            return value.Substring(0, 4) + new string('*', Math.Min(value.Length - 8, 20)) + value.Substring(value.Length - 4);
        }


    }
}
