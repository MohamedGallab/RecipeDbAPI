using FluentMigrator;

namespace Data.Migrations;

[Migration(2)]
public class _0002_Constraints  : Migration
{
	public override void Up()
	{
		Execute.Sql("ALTER TABLE Recipe WITH CHECK ADD CONSTRAINT RecipeTitleNotEmpty CHECK (Len(RTrim(Title)) > 0)");
		Execute.Sql("ALTER TABLE Category WITH CHECK ADD CONSTRAINT CategoryNotEmpty CHECK (Name <> '')");
	}
	public override void Down()
	{
		Execute.Sql("ALTER TABLE Recipe DROP CONSTRAINT RecipeTitleNotEmpty");
		Execute.Sql("ALTER TABLE Category DROP CONSTRAINT CategoryNotEmpty");
	}
}
