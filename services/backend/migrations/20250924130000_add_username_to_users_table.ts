import type { Knex } from "knex";

export async function up(knex: Knex): Promise<void> {
  const hasColumn = await knex.schema.hasColumn("users", "username");
  if (!hasColumn) {
    await knex.schema.alterTable("users", (table) => {
      table.string("username").notNullable().unique();
    });
  }
}

export async function down(knex: Knex): Promise<void> {
  const hasColumn = await knex.schema.hasColumn("users", "username");
  if (hasColumn) {
    await knex.schema.alterTable("users", (table) => {
      table.dropColumn("username");
    });
  }
}
