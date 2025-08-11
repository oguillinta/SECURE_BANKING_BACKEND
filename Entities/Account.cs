namespace ApiSecureBank.Entities
{
    public class Account
    {
        public int Id { get; set; }
        public String? accountNumber { get; set; } = null!;
        public String? customerId { get; set; } = null!;
        public String? accountType { get; set; } = null!;
        public decimal balance { get; set; }
        public decimal dailyTransactionLimit { get; set; }
        public String? status { get; set; }
        public DateTime? createdAt { get; set; }
        public DateTime? updatedAt { get; set; }
        public String? freezeReason { get; set; }
        public String? freezeType { get; set; }
        public DateTime? freezeDate { get; set; }
        public String? frozenBy { get; set; }
        public DateTime? DATETIME2 { get; set; }
        public String? freezeReferenceNumber { get; set; }
    }
}
