use crate::QueryError;
use sha1::{Digest, Sha1};
use sqlparser::ast::{
    Expr, Function, FunctionArg, FunctionArgExpr, FunctionArguments, SelectItem, SetExpr,
    Statement, Value, ValueWithSpan,
};
use sqlparser::dialect::MySqlDialect;
use sqlparser::parser::Parser;
use sqlparser::tokenizer::Span;

fn replace_values_with_placeholders(statement: &mut Statement) {
    match statement {
        Statement::Query(query) => {
            if let SetExpr::Select(select) = query.body.as_mut() {
                if let Some(ref mut selection) = select.selection {
                    replace_values_in_expr(selection);
                }

                for item in &mut select.projection {
                    replace_values_in_select_item(item);
                }
            }
        }
        Statement::Update(update) => {
            for assignment in &mut update.assignments {
                replace_values_in_expr(&mut assignment.value);
            }
            if let Some(ref mut selection) = update.selection {
                replace_values_in_expr(selection);
            }
        }
        Statement::Insert(insert) => {
            let source = insert.source.as_mut();
            if let Some(source) = source {
                if let SetExpr::Values(values) = source.body.as_mut() {
                    for value in &mut values.rows {
                        for expr in value {
                            replace_values_in_expr(expr);
                        }
                    }
                }
            }
        }
        Statement::Delete(delete) => {
            if let Some(ref mut selection) = delete.selection {
                replace_values_in_expr(selection);
            }
        }
        _ => {}
    }
}

fn replace_values_in_select_item(select_item: &mut SelectItem) {
    match select_item {
        SelectItem::UnnamedExpr(expr) | SelectItem::ExprWithAlias { expr, .. } => {
            replace_values_in_expr(expr);
        }
        SelectItem::QualifiedWildcard(..) | SelectItem::Wildcard(..) => {}
    }
}

fn replace_values_in_function(func: &mut Function) {
    if let FunctionArguments::List(list) = &mut func.args {
        for arg in &mut list.args {
            match arg {
                FunctionArg::Unnamed(expr) => {
                    if let FunctionArgExpr::Expr(expr) = expr {
                        replace_values_in_expr(expr);
                    }
                }
                FunctionArg::Named { arg, .. } => {
                    if let FunctionArgExpr::Expr(expr) = arg {
                        replace_values_in_expr(expr);
                    }
                }
                FunctionArg::ExprNamed { name, arg, .. } => {
                    replace_values_in_expr(name);
                    if let FunctionArgExpr::Expr(expr) = arg {
                        replace_values_in_expr(expr);
                    }
                }
            }
        }
    }
}

fn replace_values_in_expr(expr: &mut Expr) {
    match expr {
        Expr::Value(_) => {
            *expr = Expr::Value(ValueWithSpan {
                value: Value::Placeholder("?".to_string()),
                span: Span::empty(),
            });
        }
        Expr::Case {
            operand,
            conditions,
            else_result,
            ..
        } => {
            for case_when in conditions {
                replace_values_in_expr(&mut case_when.condition);
                replace_values_in_expr(&mut case_when.result);
            }
            if let Some(operand) = operand.as_mut() {
                replace_values_in_expr(operand);
            }
            if let Some(else_result) = else_result.as_mut() {
                replace_values_in_expr(else_result);
            }
        }
        Expr::Extract { expr, .. }
        | Expr::Collate { expr, .. }
        | Expr::Nested(expr)
        | Expr::Ceil { expr, .. }
        | Expr::Floor { expr, .. }
        | Expr::Convert { expr, .. }
        | Expr::Cast { expr, .. }
        | Expr::IsNull(expr)
        | Expr::IsNotNull(expr)
        | Expr::IsTrue(expr)
        | Expr::IsNotTrue(expr)
        | Expr::IsFalse(expr)
        | Expr::IsNotFalse(expr)
        | Expr::IsUnknown(expr)
        | Expr::IsNotUnknown(expr)
        | Expr::UnaryOp { expr, .. } => {
            replace_values_in_expr(expr);
        }
        Expr::BinaryOp { left, right, .. } => {
            replace_values_in_expr(left);
            replace_values_in_expr(right);
        }
        Expr::Like { expr, pattern, .. } => {
            replace_values_in_expr(expr);
            replace_values_in_expr(pattern);
        }
        Expr::InList { expr, list, .. } => {
            replace_values_in_expr(expr);
            for expr in list {
                replace_values_in_expr(expr);
            }
        }
        Expr::Between {
            expr, low, high, ..
        } => {
            replace_values_in_expr(expr);
            replace_values_in_expr(low);
            replace_values_in_expr(high);
        }
        Expr::Function(func) => {
            replace_values_in_function(func);
        }
        Expr::Subquery(query) => {
            if let SetExpr::Select(select) = query.body.as_mut() {
                if let Some(ref mut selection) = select.selection {
                    replace_values_in_expr(selection);
                } else {
                    for item in &mut select.projection {
                        replace_values_in_select_item(item);
                    }
                }
            }
        }
        Expr::InSubquery { expr, subquery, .. } => {
            if let SetExpr::Select(select) = subquery.body.as_mut() {
                if let Some(ref mut selection) = select.selection {
                    replace_values_in_expr(selection);
                } else {
                    for item in &mut select.projection {
                        replace_values_in_select_item(item);
                    }
                }
            }
            replace_values_in_expr(expr);
        }
        Expr::GroupingSets(grouping_sets) => {
            for set in grouping_sets {
                for expr in set {
                    replace_values_in_expr(expr);
                }
            }
        }
        _ => {}
    }
}

/// Formats a SQL query by replacing all literal values with placeholders.
///
/// This function parses the input SQL query, replaces all literal values
/// (strings, numbers, etc.) with `?` placeholders, and returns the Normalised
/// query string. This is useful for query fingerprinting and grouping similar
/// queries together.
///
/// Returns `QueryError::ParseError` if the SQL cannot be parsed.
/// Returns `QueryError::InvalidQuery` if no SQL statement is found.
pub(crate) fn format_query(input: &str) -> Result<String, QueryError> {
    let ast = Parser::parse_sql(&MySqlDialect {}, input)?;
    let mut query = ast.into_iter().next().ok_or(QueryError::InvalidQuery)?;

    replace_values_with_placeholders(&mut query);
    Ok(query.to_string())
}

/// Calculates SHA1 hash fingerprint of a query
pub(crate) fn fingerprint_query(query: &str) -> String {
    let mut hasher = Sha1::new();
    hasher.update(query.as_bytes());
    let result = hasher.finalize();
    format!("{result:x}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_select_with_operators() {
        let input = "select * from tablename where id = 1 and name like 'test' and age > 10 and age < 20 and age != 30 and age <> 40";
        let expected = "SELECT * FROM tablename WHERE id = ? AND name LIKE ? AND age > ? AND age < ? AND age <> ? AND age <> ?";
        let replaced = format_query(input).unwrap();
        assert_eq!(replaced, expected);
    }

    #[test]
    fn test_select_with_in() {
        let input = "select * from tablename where id in (1,2,3) and name not in (4,5,6)";
        let expected = "SELECT * FROM tablename WHERE id IN (?, ?, ?) AND name NOT IN (?, ?, ?)";
        let replaced = format_query(input).unwrap();
        assert_eq!(replaced, expected);
    }

    #[test]
    fn test_select_with_between() {
        let input = "select * from tablename where age between 10 and 20";
        let expected = "SELECT * FROM tablename WHERE age BETWEEN ? AND ?";
        let replaced = format_query(input).unwrap();
        assert_eq!(replaced, expected);
    }

    #[test]
    fn test_select_with_like() {
        let input = "select * from tablename where age like '%test%'";
        let expected = "SELECT * FROM tablename WHERE age LIKE ?";
        let replaced = format_query(input).unwrap();
        assert_eq!(replaced, expected);
    }

    #[test]
    fn test_select_with_grouping() {
        let input = "select IF(GROUPING(b)=1, 'Test', b) as thing from tablename";
        let expected = "SELECT IF(GROUPING(b) = ?, ?, b) AS thing FROM tablename";
        let replaced = format_query(input).unwrap();
        assert_eq!(replaced, expected);
    }

    #[test]
    fn test_select_with_subquery() {
        let input = "select (SELECT id FROM foobar WHERE id=1) from tablename";
        let expected = "SELECT (SELECT id FROM foobar WHERE id = ?) FROM tablename";
        let replaced = format_query(input).unwrap();
        assert_eq!(replaced, expected);
    }

    #[test]
    fn test_select_with_function() {
        let input = "select max(1, ceil(123)) as thing from tablename";
        let expected = "SELECT max(?, CEIL(?)) AS thing FROM tablename";
        let replaced = format_query(input).unwrap();
        assert_eq!(replaced, expected);
    }

    #[test]
    fn test_select_with_case() {
        let input =
            "select case when age > 18 then 'adult' else 'child' end as age_group from tablename";
        let expected = "SELECT CASE WHEN age > ? THEN ? ELSE ? END AS age_group FROM tablename";
        let replaced = format_query(input).unwrap();
        assert_eq!(replaced, expected);
    }

    #[test]
    fn test_select_with_all() {
        let input = "select (SELECT id FROM foobar WHERE id=1), max(1, ceil(123)) as thing, IF(GROUPING(b)=1, 'All Employees', b) as Employees, * from tablename where id = 1 and name = 'test' and age > 10 and age < 20 and age != 30 and age <> 40 and age in (1,2,3) and age not in (4,5,6) and age between 10 and 20 and age like '\"%test%\"' and age not like '%test%'";
        let expected = "SELECT (SELECT id FROM foobar WHERE id = ?), max(?, CEIL(?)) AS thing, IF(GROUPING(b) = ?, ?, b) AS Employees, * FROM tablename WHERE id = ? AND name = ? AND age > ? AND age < ? AND age <> ? AND age <> ? AND age IN (?, ?, ?) AND age NOT IN (?, ?, ?) AND age BETWEEN ? AND ? AND age LIKE ? AND age NOT LIKE ?";
        let replaced = format_query(input).unwrap();
        assert_eq!(replaced, expected);
    }

    #[test]
    fn test_update() {
        let input = "UPDATE users SET foobar='foobar' WHERE age > 18 AND name LIKE '%test%' AND age BETWEEN 18 AND 100";
        let expected =
            "UPDATE users SET foobar = ? WHERE age > ? AND name LIKE ? AND age BETWEEN ? AND ?";
        let replaced = format_query(input).unwrap();
        assert_eq!(replaced, expected);
    }

    #[test]
    fn test_insert() {
        let input = "INSERT INTO users (name, age) VALUES ('test', 20)";
        let expected = "INSERT INTO users (name, age) VALUES (?, ?)";
        let replaced = format_query(input).unwrap();
        assert_eq!(replaced, expected);
    }

    #[test]
    fn test_delete() {
        let input =
            "DELETE FROM users WHERE age > 18 AND name LIKE '%test%' AND age BETWEEN 18 AND 100";
        let expected = "DELETE FROM users WHERE age > ? AND name LIKE ? AND age BETWEEN ? AND ?";
        let replaced = format_query(input).unwrap();
        assert_eq!(replaced, expected);
    }

    #[test]
    fn test_invalid_query() {
        let input = "select * from";
        let result = format_query(input);
        assert!(matches!(result, Err(QueryError::ParseError(_))));
    }

    #[test]
    fn test_fingerprint_query() {
        let query = "SELECT * FROM table WHERE id = 1";
        let fingerprint = fingerprint_query(query);
        assert_eq!(fingerprint, "a0b2ab83e88b7d55eec3d242dd27ff2bbb0e06cf");
    }
}
