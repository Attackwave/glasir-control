//! HTTP requests in one tree of a workspace that reach a route in another.
//!
//! Each Core reports its routes and requests through the `http_surface` tool,
//! reduced to segments with a parameter as `*`. Joining them is the Core's own
//! rule, applied across trees: the verbs agree, every segment agrees, a
//! parameter in the route takes any segment, and among the routes a request
//! reaches, only those with the most literal segments count, as every router
//! decides it.

use serde_json::{Value, json};

struct Route<'a> {
    tree: &'a str,
    handler: &'a str,
    verb: &'a str,
    segments: Vec<&'a str>,
}

fn segments(v: &Value) -> Vec<&str> {
    v.as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect()
}

fn reaches(request: (&str, &[&str]), route: (&str, &[&str])) -> bool {
    let verbs = request.0 == "ANY" || route.0 == "ANY" || request.0 == route.0;
    verbs
        && request.1.len() == route.1.len()
        && request
            .1
            .iter()
            .zip(route.1)
            .all(|(q, r)| *r == "*" || (*q != "*" && q == r))
}

/// Every request of a tree that reaches a route of a different tree, given
/// each tree's `http_surface` answer.
pub fn links(surfaces: &[(String, Value)]) -> Vec<Value> {
    let routes: Vec<Route> = surfaces
        .iter()
        .flat_map(|(tree, surface)| {
            surface["routes"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(move |r| {
                    Some(Route {
                        tree,
                        handler: r["handler"].as_str()?,
                        verb: r["verb"].as_str()?,
                        segments: segments(&r["segments"]),
                    })
                })
        })
        .collect();
    let mut out = Vec::new();
    for (tree, surface) in surfaces {
        for request in surface["requests"].as_array().into_iter().flatten() {
            let (Some(sender), Some(verb)) = (request["sender"].as_str(), request["verb"].as_str())
            else {
                continue;
            };
            let asked = segments(&request["segments"]);
            if asked.is_empty() {
                continue;
            }
            let reached: Vec<(&Route, usize)> = routes
                .iter()
                .filter(|r| r.tree != tree && reaches((verb, &asked), (r.verb, &r.segments)))
                .map(|r| (r, r.segments.iter().filter(|s| **s != "*").count()))
                .collect();
            let best = reached.iter().map(|&(_, literal)| literal).max();
            for (route, literal) in reached {
                if Some(literal) == best {
                    out.push(json!({
                        "from_tree": tree,
                        "sender": sender,
                        "verb": verb,
                        "path": request["path"],
                        "to_tree": route.tree,
                        "handler": route.handler,
                    }));
                }
            }
        }
    }
    out
}

/// The links whose handler is among a tree's changed symbols, grouped by
/// handler: who in another repository calls what this change touches.
pub fn callers_of_changes(links: &[Value], changed: &[(String, Vec<String>)]) -> Vec<Value> {
    let mut out = Vec::new();
    for (tree, symbols) in changed {
        for symbol in symbols {
            let callers: Vec<Value> = links
                .iter()
                .filter(|l| l["to_tree"] == tree.as_str() && l["handler"] == symbol.as_str())
                .map(|l| json!({"tree": l["from_tree"], "sender": l["sender"], "verb": l["verb"], "path": l["path"]}))
                .collect();
            if !callers.is_empty() {
                out.push(json!({"tree": tree, "handler": symbol, "callers": callers}));
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_request_reaches_the_most_specific_route_of_another_tree_only() {
        let server = json!({
            "routes": [
                {"handler": "Api.java#show", "verb": "GET", "segments": ["items", "*"]},
                {"handler": "Api.java#by", "verb": "GET", "segments": ["items", "by"]},
                {"handler": "Api.java#drop", "verb": "DELETE", "segments": ["items", "*"]}
            ],
            "requests": [
                // The server calling itself is the Core's business, not a link.
                {"sender": "Api.java#self", "verb": "GET", "path": "/items/1", "segments": ["items", "*"]}
            ]
        });
        let client = json!({
            "routes": [],
            "requests": [
                {"sender": "a.ts#one", "verb": "GET", "path": "/items/{}", "segments": ["items", "*"]},
                {"sender": "a.ts#some", "verb": "GET", "path": "/items/by", "segments": ["items", "by"]},
                {"sender": "a.ts#gone", "verb": "POST", "path": "/items/{}", "segments": ["items", "*"]}
            ]
        });
        let all = links(&[("server".into(), server), ("client".into(), client)]);
        let pairs: Vec<(&str, &str)> = all
            .iter()
            .map(|l| {
                (
                    l["sender"].as_str().unwrap(),
                    l["handler"].as_str().unwrap(),
                )
            })
            .collect();
        assert_eq!(
            pairs,
            [("a.ts#one", "Api.java#show"), ("a.ts#some", "Api.java#by")]
        );

        let changed = [(
            "server".to_string(),
            vec!["Api.java#show".to_string(), "Api.java#drop".to_string()],
        )];
        let callers = callers_of_changes(&all, &changed);
        assert_eq!(callers.len(), 1, "{callers:?}");
        assert_eq!(callers[0]["handler"], "Api.java#show");
        assert_eq!(callers[0]["callers"][0]["tree"], "client");
    }
}
