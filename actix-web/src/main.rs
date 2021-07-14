use actix_web::{get, web, App, HttpResponse, HttpServer, Responder};
use serde::Serialize;
use std::collections::HashMap;

#[get("/hello/{name}")]
async fn greet(name: web::Path<String>) -> impl Responder {
    format!("Hello {}!", name)
}

#[derive(Serialize, Clone)]
struct Person {
    id: String,
    name: String,
}

#[derive(Serialize, Clone)]
struct ResponseBody {
    message: String,
}

#[get("/people/{id}")]
async fn person(id: web::Path<String>) -> impl Responder {
    let mut map = HashMap::new();
    let p1 = Person {
        id: "1".to_string(),
        name: "john".to_string(),
    };
    let p2 = Person {
        id: "2".to_string(),
        name: "paul".to_string(),
    };
    map.insert("1", p1);
    map.insert("2", p2);

    let key: &str = &id;
    match map.get_mut(key) {
        Some(person) => HttpResponse::Ok().json(person),
        _ => HttpResponse::NotFound().json(ResponseBody {
            message: "Data Not Found".to_string(),
        }),
    }
}

#[get("/people")]
async fn people(_: web::Path<()>) -> impl Responder {
    let p1 = Person {
        id: "1".to_string(),
        name: "john".to_string(),
    };
    let p2 = Person {
        id: "2".to_string(),
        name: "paul".to_string(),
    };
    web::Json(vec![p1, p2])
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    HttpServer::new(|| App::new().service(greet).service(person).service(people))
        .bind("127.0.0.1:8080")?
        .run()
        .await
}
