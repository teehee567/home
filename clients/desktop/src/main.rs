slint::slint! {
    export component App inherits Window {
        title: "Home";
        width: 800px;
        height: 600px;

        Text {
            text: "Home";
        }
    }
}

fn main() {
    let app = App::new().unwrap();
    app.run().unwrap();
}
