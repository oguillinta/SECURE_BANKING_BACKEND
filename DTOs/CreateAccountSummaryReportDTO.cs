namespace ApiSecureBank.DTOs
{
    public class CreateAccountSummaryReportDTO
    {
        public int Id { get; set; }
        public string accountType { get; set; } = null!;
        public int totalAccounts { get; set; }
        public decimal totalBalance { get; set; }
        public decimal averageBalance { get; set; }
        public int activeAccountsCount { get; set; }
        public int frozenAccountsCount { get; set; }
        public int closedAccountsCount { get; set; }
        public DateTime reportGeneratedAt { get; set; }
    }
}
