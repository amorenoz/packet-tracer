use std::{collections::HashMap, path::PathBuf, rc::Rc, time::Duration};

use pyo3::{
    exceptions::{PyKeyError, PyRuntimeError},
    prelude::PyAnyMethods,
    prelude::*,
};

mod cli;
mod collect;
mod core;
mod generate;
mod module;
mod process;
mod profiles;

// Re-export derive macros.
use retis_derive::*;

use core::events::{file::FileEventsFactory, *};
use module::ModuleId;

/// Python representation of an Event.
///
/// We can't directly convert an Event to a Python representation because it
/// contains a map of trait implementation. We could just represent it as a
/// Python map, but using an object around it makes implementing custom methods
/// possible.
#[pyclass(unsendable)]
#[derive(Clone)]
pub(crate) struct PyEvent(Rc<Event>);

impl PyEvent {
    pub(crate) fn new(event: Event) -> Self {
        Self(Rc::new(event))
    }
}

impl ToPyObject for PyEvent {
    fn to_object(&self, py: Python<'_>) -> PyObject {
        self.clone().into_py(py)
    }
}

#[pymethods]
impl PyEvent {
    /// Controls how the PyEvent is represented, eg. what is the output of
    /// `print(e)`.
    fn __repr__<'a>(&'a self, py: Python<'a>) -> String {
        let raw = self.raw(py);
        let dict: &Bound<'_, PyAny> = raw.bind(py);
        dict.repr().unwrap().to_string()
    }

    /// Allows to use the object as a dictionary, eg. `e['skb']`.
    fn __getitem__<'a>(&'a self, py: Python<'a>, attr: &str) -> PyResult<Py<PyAny>> {
        if let Ok(id) = ModuleId::from_str(attr) {
            if let Some(section) = self.0.get(id) {
                return Ok(section.to_py(py));
            }
        }
        Err(PyKeyError::new_err(attr.to_string()))
    }

    /// Returns a dictionary with all key<>data stored (recursively) in the
    /// event, eg. `e.raw()['skb']['dev']`.
    fn raw(&self, py: Python<'_>) -> PyObject {
        to_pyobject(&self.0.to_json(), py)
    }

    /// Maps to our own logic to show the event, so we can print it like Retis
    /// would do in collect or print.
    fn show(&self) -> String {
        format!("{}", self.0.display(DisplayFormat::MultiLine))
    }
}

/// Converts a serde_json::Value to a PyObject.
pub(crate) fn to_pyobject(val: &serde_json::Value, py: Python<'_>) -> PyObject {
    use serde_json::Value;
    match val {
        Value::Null => py.None().into(),
        Value::Bool(b) => b.to_object(py),
        Value::Number(n) => n
            .as_i64()
            .map(|x| x.to_object(py))
            .or(n.as_u64().map(|x| x.to_object(py)))
            .or(n.as_f64().map(|x| x.to_object(py)))
            .expect("Cannot convert number to Python object"),
        Value::String(s) => s.to_object(py),
        Value::Array(a) => {
            let vec: Vec<_> = a.iter().map(|x| to_pyobject(x, py)).collect();
            vec.to_object(py)
        }
        Value::Object(o) => {
            let map: HashMap<_, _> = o.iter().map(|(k, v)| (k, to_pyobject(v, py))).collect();
            map.to_object(py)
        }
    }
}

/// Python wrapper of a FileEventsFactory.
#[pyclass(unsendable)]
pub(crate) struct PyEventReader {
    factory: FileEventsFactory,
}
#[pymethods]
impl PyEventReader {
    pub(crate) fn next(&mut self) -> PyResult<Option<PyEvent>> {
        use EventResult::*;
        match self
            .factory
            .next_event(Some(Duration::from_secs(1)))
            .map_err(|e| PyRuntimeError::new_err(e.to_string()))?
        {
            Event(event) => Ok(Some(PyEvent::new(event))),
            Eof => Ok(None),
            Timeout => Err(PyRuntimeError::new_err("timeout")),
        }
    }

    #[new]
    pub(crate) fn new(path_str: String) -> PyResult<Self> {
        let path = PathBuf::from(path_str);
        let mut factory =
            FileEventsFactory::new(path).map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
        let modules = module::get_modules().map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
        factory
            .start(
                modules
                    .section_factories()
                    .map_err(|e| PyRuntimeError::new_err(e.to_string()))?,
            )
            .map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
        Ok(PyEventReader { factory })
    }
}

#[pymodule]
fn pyretis(_py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PyEvent>()?;
    m.add_class::<PyEventReader>()?;
    Ok(())
}
