namespace ApiSecureBank.Entities
{
    public class Customer
    {
        public int Id { get; set; }
        public String? firstName { get; set; } = null!;
        public String? lastName { get; set; } = null!;
        public String? email { get; set; } = null!;
        public String? customerType { get; set; } = null!;
        public String? status { get; set; }
        public DateTime createdAt { get; set; }
        public DateTime? updatedAt { get; set; }
    }
}
