use super::QueryError;
use sha1::{Digest, Sha1};
use sqlparser::ast::{
    Expr, Function, FunctionArg, FunctionArgExpr, FunctionArguments, OnInsert, SelectItem, SetExpr,
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
            if let Some(ref mut limit_clause) = query.limit_clause {
                match limit_clause {
                    sqlparser::ast::LimitClause::LimitOffset { limit, offset, .. } => {
                        if let Some(limit) = limit {
                            replace_values_in_expr(limit);
                        }
                        if let Some(offset) = offset {
                            replace_values_in_expr(&mut offset.value);
                        }
                    }
                    sqlparser::ast::LimitClause::OffsetCommaLimit { offset, limit } => {
                        replace_values_in_expr(offset);
                        replace_values_in_expr(limit);
                    }
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
            if let Some(source) = insert.source.as_mut() {
                match source.body.as_mut() {
                    SetExpr::Values(values) => {
                        for value in &mut values.rows {
                            for expr in value {
                                replace_values_in_expr(expr);
                            }
                        }
                    }
                    SetExpr::Select(select) => {
                        if let Some(ref mut selection) = select.selection {
                            replace_values_in_expr(selection);
                        }
                        for item in &mut select.projection {
                            replace_values_in_select_item(item);
                        }
                        if let Some(ref mut having) = select.having {
                            replace_values_in_expr(having);
                        }
                    }
                    _ => {}
                }
            }
            if let Some(OnInsert::DuplicateKeyUpdate(assignments)) = &mut insert.on {
                for assignment in assignments {
                    replace_values_in_expr(&mut assignment.value);
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

#[allow(clippy::too_many_lines)]
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
            *list = vec![Expr::Value(ValueWithSpan {
                value: Value::Placeholder("?".to_string()),
                span: Span::empty(),
            })];
        }
        Expr::Between {
            expr, low, high, ..
        } => {
            replace_values_in_expr(expr);
            replace_values_in_expr(low);
            replace_values_in_expr(high);
        }
        Expr::Interval(interval) => {
            replace_values_in_expr(&mut interval.value);
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
#[allow(clippy::format_collect)]
pub(crate) fn fingerprint_query(query: &str) -> String {
    let mut hasher = Sha1::new();
    hasher.update(query.as_bytes());
    let result = hasher.finalize();
    result.iter().map(|b| format!("{b:02x}")).collect()
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
        let expected = "SELECT * FROM tablename WHERE id IN (?) AND name NOT IN (?)";
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
        let expected = "SELECT (SELECT id FROM foobar WHERE id = ?), max(?, CEIL(?)) AS thing, IF(GROUPING(b) = ?, ?, b) AS Employees, * FROM tablename WHERE id = ? AND name = ? AND age > ? AND age < ? AND age <> ? AND age <> ? AND age IN (?) AND age NOT IN (?) AND age BETWEEN ? AND ? AND age LIKE ? AND age NOT LIKE ?";
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
    fn test_insert_select() {
        let input = "INSERT INTO balances (user_id, amount, status) SELECT orders.user_id, SUM(orders.amount) AS amount, orders.status FROM orders INNER JOIN users ON orders.user_id = users.id WHERE orders.user_id IN (1, 2) AND orders.status IN ('active', 'pending') AND users.active = 1 GROUP BY orders.user_id, orders.status HAVING SUM(orders.amount) <> 0 ON DUPLICATE KEY UPDATE amount = IF(VALUES(status) > status, VALUES(amount), amount)";
        let expected = "INSERT INTO balances (user_id, amount, status) SELECT orders.user_id, SUM(orders.amount) AS amount, orders.status FROM orders INNER JOIN users ON orders.user_id = users.id WHERE orders.user_id IN (?) AND orders.status IN (?) AND users.active = ? GROUP BY orders.user_id, orders.status HAVING SUM(orders.amount) <> ? ON DUPLICATE KEY UPDATE amount = IF(VALUES(status) > status, VALUES(amount), amount)";
        assert_eq!(format_query(input).unwrap(), expected);
    }

    #[test]
    fn test_select_with_interval() {
        let input = "SELECT * FROM tablename WHERE created_at > NOW() - INTERVAL 7 DAY";
        let expected = "SELECT * FROM tablename WHERE created_at > NOW() - INTERVAL ? DAY";
        assert_eq!(format_query(input).unwrap(), expected);
    }

    #[test]
    fn test_select_with_limit_offset() {
        let input = "SELECT * FROM tablename WHERE id = 1 LIMIT 10 OFFSET 20";
        let expected = "SELECT * FROM tablename WHERE id = ? LIMIT ? OFFSET ?";
        assert_eq!(format_query(input).unwrap(), expected);
    }

    #[test]
    fn test_select_with_limit_only() {
        let input = "SELECT * FROM tablename LIMIT 100";
        let expected = "SELECT * FROM tablename LIMIT ?";
        assert_eq!(format_query(input).unwrap(), expected);
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
