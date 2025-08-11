namespace ApiSecureBank.DTOs
{
    public class CreateAccountDTO
    {
        public String accountNumber { get; set; } = null!;
        public String customerId { get; set; } = null!;
        public String accountType { get; set; } = null!;
        public double balance { get; set; }
        public double dailyTransactionLimit { get; set; }
        public Boolean status { get; set; }
        public DateTime createdAt { get; set; }
        public DateTime updatedAt { get; set; }
        public String? freezeReason { get; set; }
        public String? freezeType { get; set; }
        public DateTime freezeDate { get; set; }
        public String? frozenBy { get; set; }
        public DateTime DATETIME2 { get; set; }
        public String? freezeReferenceNumber { get; set; }
    }
}
