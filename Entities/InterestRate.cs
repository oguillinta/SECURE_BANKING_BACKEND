namespace ApiSecureBank.Entities
{
    public class InterestRate
    {
        public int Id { get; set; }
        public String? productType { get; set; } = null!;
        public String? productName { get; set; } = null!;
        public Decimal? rate { get; set; }
        public String? term { get; set; } = null!;
        public Decimal? minimumAmount { get; set; }
        public Decimal? maximumAmount { get; set; }
        public String? description { get; set; } 
        public Boolean? isActive { get; set; }
        public DateTime? effectiveDate { get; set; } 
        public DateTime? updatedAt { get; set; }
    }
}
