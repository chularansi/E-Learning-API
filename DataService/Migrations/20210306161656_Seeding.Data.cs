using Microsoft.EntityFrameworkCore.Migrations;

namespace DataService.Migrations
{
    public partial class SeedingData : Migration
    {
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.InsertData(
                table: "AspNetRoles",
                columns: new[] { "Id", "ConcurrencyStamp", "Name", "NormalizedName" },
                values: new object[,]
                {
                    { 1, "a19fd19a-8f86-441a-a590-5ccfbf8313b3", "Admin", "ADMIN" },
                    { 2, "2408f7a1-a511-45e9-bb97-6e1f15af5655", "Student", "STUDENT" }
                });

            migrationBuilder.InsertData(
                table: "AspNetUsers",
                columns: new[] { "Id", "AccessFailedCount", "ConcurrencyStamp", "Email", "EmailConfirmed", "FirstName", "LastName", "LockoutEnabled", "LockoutEnd", "NormalizedEmail", "NormalizedUserName", "PasswordHash", "PhoneNumber", "PhoneNumberConfirmed", "SecurityStamp", "TwoFactorEnabled", "UserName" },
                values: new object[,]
                {
                    { 1, 0, "863e1382-e9e5-4b04-b6d5-7cc05a3aae81", "admin@abc.no", true, "Super", "Admin", false, null, "ADMIN@ABC.NO", "ADMIN@ABC.NO", "AQAAAAEAACcQAAAAECHeUMFxQLN8e0Msor73jaB3p4BxbGC4Ciwy/f0TD4IGpy9s5jzH+to7VMo4ymF4fQ==", "1234567895", false, "94785b78-7be4-469a-9ca6-c538c5eee60d", true, "admin@abc.no" },
                    { 2, 0, "9223f0a9-d2ca-44b1-8c40-0622d42306d0", "student1@abc.no", true, "Master", "Student", false, null, "STUDENT1@ABC.NO", "STUDENT1@ABC.NO", "AQAAAAEAACcQAAAAEKy6ubFcyoDgJj9f47E2M6fEXMr2W75VLC00dWt8QlWWGMc4x4t2CHbSW6YrWAE7Mw==", "1234567895", false, "139aa371-9371-47bf-a75b-56f539854242", false, "student1@abc.no" }
                });

            migrationBuilder.InsertData(
                table: "AspNetUserRoles",
                columns: new[] { "RoleId", "UserId" },
                values: new object[] { 1, 1 });
        }

        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DeleteData(
                table: "AspNetRoles",
                keyColumn: "Id",
                keyValue: 2);

            migrationBuilder.DeleteData(
                table: "AspNetUserRoles",
                keyColumns: new[] { "RoleId", "UserId" },
                keyValues: new object[] { 1, 1 });

            migrationBuilder.DeleteData(
                table: "AspNetUsers",
                keyColumn: "Id",
                keyValue: 2);

            migrationBuilder.DeleteData(
                table: "AspNetRoles",
                keyColumn: "Id",
                keyValue: 1);

            migrationBuilder.DeleteData(
                table: "AspNetUsers",
                keyColumn: "Id",
                keyValue: 1);
        }
    }
}
