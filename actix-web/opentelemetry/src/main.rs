use actix_service::Service;
use actix_web::{get, web, App, HttpServer, Responder};
use opentelemetry::global;
use opentelemetry::{
    sdk::export::trace::stdout,
    trace::{FutureExt, TraceContextExt, Tracer},
};

#[get("/hello/{name}")]
async fn greet(name: web::Path<String>) -> impl Responder {
    let tracer = global::tracer("request");
    let (tid, sid) = tracer.in_span("req", move |cx| {
        (
            cx.span().span_context().trace_id().to_u128(),
            cx.span().span_context().span_id().to_u64(),
        )
    });
    println!("trace/span id is {}/{}.", tid, sid);
    format!("Hello {}!", name)
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let tracer = stdout::new_pipeline().install_simple();

    HttpServer::new(move || {
        let tracer = tracer.clone();
        App::new()
            .wrap_fn(move |req, srv| {
                tracer.in_span("middleware", move |cx| {
                    let tid = cx.span().span_context().trace_id().to_u128();
                    let sid = cx.span().span_context().span_id().to_u64();
                    println!("trace/span id is {}/{}.", tid, sid);
                    srv.call(req).with_context(cx)
                })
            })
            .service(greet)
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}
