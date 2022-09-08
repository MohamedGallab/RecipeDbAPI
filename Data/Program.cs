using Data.Migrations;
using FluentMigrator.Runner;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddFluentMigratorCore()
				.ConfigureRunner(rb => rb
					.AddSqlServer()
					.WithGlobalConnectionString(builder.Configuration["ConnectionStrings:DefaultConnection"])
					.ScanIn(typeof(_0001_CreateTables).Assembly).For.Migrations())
				.AddLogging(lb => lb.AddFluentMigratorConsole());

var app = builder.Build();

using (var scope = app.Services.CreateScope())
{
	var runner = scope.ServiceProvider.GetRequiredService<IMigrationRunner>();

	runner.MigrateUp();
}

app.Run();