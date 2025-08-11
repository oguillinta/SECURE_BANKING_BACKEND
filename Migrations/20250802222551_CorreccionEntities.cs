using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace ApiSecureBank.Migrations
{
    /// <inheritdoc />
    public partial class CorreccionEntities : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "balance",
                table: "Customers");

            migrationBuilder.DropColumn(
                name: "dailyTransactionLimit",
                table: "Customers");

            migrationBuilder.DropColumn(
                name: "TypeAccountId",
                table: "Accounts");

            migrationBuilder.RenameColumn(
                name: "customerId",
                table: "Customers",
                newName: "lastName");

            migrationBuilder.RenameColumn(
                name: "accountType",
                table: "Customers",
                newName: "firstName");

            migrationBuilder.RenameColumn(
                name: "accountNumber",
                table: "Customers",
                newName: "email");

            migrationBuilder.RenameColumn(
                name: "CustomerId",
                table: "Accounts",
                newName: "customerId");

            migrationBuilder.RenameColumn(
                name: "Opened",
                table: "Accounts",
                newName: "updatedAt");

            migrationBuilder.RenameColumn(
                name: "Name",
                table: "Accounts",
                newName: "accountType");

            migrationBuilder.RenameColumn(
                name: "LastUpdated",
                table: "Accounts",
                newName: "freezeDate");

            migrationBuilder.RenameColumn(
                name: "DailyLimit",
                table: "Accounts",
                newName: "dailyTransactionLimit");

            migrationBuilder.RenameColumn(
                name: "CurrentBalance",
                table: "Accounts",
                newName: "balance");

            migrationBuilder.RenameColumn(
                name: "Active",
                table: "Accounts",
                newName: "status");

            migrationBuilder.AlterColumn<bool>(
                name: "status",
                table: "Customers",
                type: "bit",
                nullable: false,
                defaultValue: false,
                oldClrType: typeof(string),
                oldType: "nvarchar(max)",
                oldNullable: true);

            migrationBuilder.AddColumn<string>(
                name: "customerType",
                table: "Customers",
                type: "nvarchar(max)",
                nullable: false,
                defaultValue: "");

            migrationBuilder.AlterColumn<string>(
                name: "customerId",
                table: "Accounts",
                type: "nvarchar(max)",
                nullable: false,
                oldClrType: typeof(int),
                oldType: "int");

            migrationBuilder.AddColumn<DateTime>(
                name: "DATETIME2",
                table: "Accounts",
                type: "datetime2",
                nullable: false,
                defaultValue: new DateTime(1, 1, 1, 0, 0, 0, 0, DateTimeKind.Unspecified));

            migrationBuilder.AddColumn<string>(
                name: "accountNumber",
                table: "Accounts",
                type: "nvarchar(max)",
                nullable: false,
                defaultValue: "");

            migrationBuilder.AddColumn<DateTime>(
                name: "createdAt",
                table: "Accounts",
                type: "datetime2",
                nullable: false,
                defaultValue: new DateTime(1, 1, 1, 0, 0, 0, 0, DateTimeKind.Unspecified));

            migrationBuilder.AddColumn<string>(
                name: "freezeReason",
                table: "Accounts",
                type: "nvarchar(max)",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "freezeReferenceNumber",
                table: "Accounts",
                type: "nvarchar(max)",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "freezeType",
                table: "Accounts",
                type: "nvarchar(max)",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "frozenBy",
                table: "Accounts",
                type: "nvarchar(max)",
                nullable: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "customerType",
                table: "Customers");

            migrationBuilder.DropColumn(
                name: "DATETIME2",
                table: "Accounts");

            migrationBuilder.DropColumn(
                name: "accountNumber",
                table: "Accounts");

            migrationBuilder.DropColumn(
                name: "createdAt",
                table: "Accounts");

            migrationBuilder.DropColumn(
                name: "freezeReason",
                table: "Accounts");

            migrationBuilder.DropColumn(
                name: "freezeReferenceNumber",
                table: "Accounts");

            migrationBuilder.DropColumn(
                name: "freezeType",
                table: "Accounts");

            migrationBuilder.DropColumn(
                name: "frozenBy",
                table: "Accounts");

            migrationBuilder.RenameColumn(
                name: "lastName",
                table: "Customers",
                newName: "customerId");

            migrationBuilder.RenameColumn(
                name: "firstName",
                table: "Customers",
                newName: "accountType");

            migrationBuilder.RenameColumn(
                name: "email",
                table: "Customers",
                newName: "accountNumber");

            migrationBuilder.RenameColumn(
                name: "customerId",
                table: "Accounts",
                newName: "CustomerId");

            migrationBuilder.RenameColumn(
                name: "updatedAt",
                table: "Accounts",
                newName: "Opened");

            migrationBuilder.RenameColumn(
                name: "status",
                table: "Accounts",
                newName: "Active");

            migrationBuilder.RenameColumn(
                name: "freezeDate",
                table: "Accounts",
                newName: "LastUpdated");

            migrationBuilder.RenameColumn(
                name: "dailyTransactionLimit",
                table: "Accounts",
                newName: "DailyLimit");

            migrationBuilder.RenameColumn(
                name: "balance",
                table: "Accounts",
                newName: "CurrentBalance");

            migrationBuilder.RenameColumn(
                name: "accountType",
                table: "Accounts",
                newName: "Name");

            migrationBuilder.AlterColumn<string>(
                name: "status",
                table: "Customers",
                type: "nvarchar(max)",
                nullable: true,
                oldClrType: typeof(bool),
                oldType: "bit");

            migrationBuilder.AddColumn<double>(
                name: "balance",
                table: "Customers",
                type: "float",
                nullable: false,
                defaultValue: 0.0);

            migrationBuilder.AddColumn<double>(
                name: "dailyTransactionLimit",
                table: "Customers",
                type: "float",
                nullable: false,
                defaultValue: 0.0);

            migrationBuilder.AlterColumn<int>(
                name: "CustomerId",
                table: "Accounts",
                type: "int",
                nullable: false,
                oldClrType: typeof(string),
                oldType: "nvarchar(max)");

            migrationBuilder.AddColumn<int>(
                name: "TypeAccountId",
                table: "Accounts",
                type: "int",
                nullable: false,
                defaultValue: 0);
        }
    }
}
