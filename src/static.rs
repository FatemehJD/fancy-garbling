// -*- mode: rust; -*-
//
// This file is part of `fancy-garbling`.
// Copyright © 2019 Galois, Inc.
// See LICENSE for licensing information.

//! Provides objects and functions for statically garbling and evaluating a
//! circuit.

use crate::circuit::Circuit;
use crate::error::{EvaluatorError, GarblerError};
use crate::fancy::HasModulus;
use crate::garble::{Evaluator, Garbler};
use crate::wire::Wire;
use itertools::Itertools;
use scuttlebutt::{AbstractChannel, AesRng, Block, Channel};
use std::collections::HashMap;
use std::convert::TryInto;
use std::rc::Rc;

/// Static evaluator for a circuit, created by the `garble` function.
///
/// Uses `Evaluator` under the hood to actually implement the evaluation.
#[derive(Debug)]
#[cfg_attr(feature = "serde1", derive(serde::Serialize, serde::Deserialize))]
pub struct GarbledCircuit {
    blocks: Vec<Block>,
}

impl GarbledCircuit {
    /// Create a new object from a vector of garbled gates and constant wires.
    pub fn new(blocks: Vec<Block>) -> Self {
        GarbledCircuit { blocks }
    }

    /// The number of garbled rows and constant wires in the garbled circuit.
    #[inline]
    pub fn size(&self) -> usize {
        self.blocks.len()
    }

    /// Evaluate the garbled circuit.
    pub fn eval(
        &self,
        c: &mut Circuit,
        garbler_inputs: &[Wire],
        evaluator_inputs: &[Wire],
    ) -> Result<Vec<u16>, EvaluatorError> {
        println!("evaluator block: {:?}", &self.blocks);
        let channel = Channel::new(GarbledReader::new(&self.blocks), GarbledWriter::new(None));
        let mut evaluator = Evaluator::new(channel);
        let outputs = c.eval(&mut evaluator, garbler_inputs, evaluator_inputs)?;
        c.process_outputs(&outputs, &mut evaluator)?;
        evaluator.decode_output()
    }

    /// Evaluate the garbled circuit and return output labels
    pub fn eval_labels(
        &self,
        c: &mut Circuit,
        garbler_inputs: &[Wire],
        evaluator_inputs: &[Wire],
    ) -> Result<Vec<Wire>, EvaluatorError> {
        let channel = Channel::new(GarbledReader::new(&self.blocks), GarbledWriter::new(None));
        let mut evaluator = Evaluator::new(channel);
        let outputs = c.eval(&mut evaluator, garbler_inputs, evaluator_inputs)?;
        c.process_outputs(&outputs, &mut evaluator)?;
        Ok(outputs)
    }
}

/// Garble a circuit without streaming. 
pub fn garble(c: &mut Circuit) -> Result<(Encoder, GarbledCircuit), GarblerError> {
    let channel = Channel::new(
        GarbledReader::new(&[]),
        GarbledWriter::new(Some(c.num_nonfree_gates)),
    );
    let channel_ = channel.clone();

    let rng = AesRng::new();
    let mut garbler = Garbler::new(channel_, rng, &[]);

    // get input wires, ignoring encoded values
    let gb_inps = (0..c.num_garbler_inputs())
        .map(|i| {
            let q = c.garbler_input_mod(i);
            let (zero, _) = garbler.encode_wire(0, q);
            zero
        })
        .collect_vec();

    let ev_inps = (0..c.num_evaluator_inputs())
        .map(|i| {
            let q = c.evaluator_input_mod(i);
            let (zero, _) = garbler.encode_wire(0, q);
            zero
        })
        .collect_vec();

    let outputs = c.eval(&mut garbler, &gb_inps, &ev_inps)?;

    c.process_outputs(&outputs, &mut garbler)?;

    let en = Encoder::new(gb_inps, ev_inps, garbler.get_deltas());

    let gc = GarbledCircuit::new(
        Rc::try_unwrap(channel.writer())
            .unwrap()
            .into_inner()
            .blocks,
    );
    Ok((en, gc))
}

/// Garble a circuit without streaming and return the output labels
pub fn garble_out(c: &mut Circuit) -> Result<((Encoder, GarbledCircuit), Vec<Wire>), GarblerError> {
    let channel = Channel::new(
        GarbledReader::new(&[]),
        GarbledWriter::new(Some(c.num_nonfree_gates)),
    );
    let channel_ = channel.clone();

    let rng = AesRng::new();
    let mut garbler = Garbler::new(channel_, rng, &[]);

    // get input wires, ignoring encoded values
    let gb_inps = (0..c.num_garbler_inputs())
        .map(|i| {
            let q = c.garbler_input_mod(i);
            let (zero, _) = garbler.encode_wire(0, q);
            zero
        })
        .collect_vec();

    let ev_inps = (0..c.num_evaluator_inputs())
        .map(|i| {
            let q = c.evaluator_input_mod(i);
            let (zero, _) = garbler.encode_wire(0, q);
            zero
        })
        .collect_vec();

    let outputs = c.eval(&mut garbler, &gb_inps, &ev_inps)?;

    c.process_outputs(&outputs, &mut garbler)?;

    let en = Encoder::new(gb_inps, ev_inps, garbler.get_deltas());

    let gc = GarbledCircuit::new(
        Rc::try_unwrap(channel.writer())
            .unwrap()
            .into_inner()
            .blocks,
    );

    Ok(((en, gc), outputs))
}

/// Garbles a circuit whose input labels are the output of another circuit
pub fn garble_chain(
    c: &mut Circuit,
    garbler_inputs: Vec<Wire>,
    eval_inputs: Vec<Wire>,
    deltas: &[Wire],
) -> Result<(Encoder, GarbledCircuit), GarblerError> {
    let channel = Channel::new(
        GarbledReader::new(&[]),
        GarbledWriter::new(Some(c.num_nonfree_gates)),
    );
    let channel_ = channel.clone();

    let rng = AesRng::new();
    let mut garbler = Garbler::new(channel_, rng, deltas);

    // The initial input wires are taken from the provided 
    // vectors. The rest are randomly generated
    let mut gb_inps = garbler_inputs;
    gb_inps.extend(
        (gb_inps.len()..c.num_garbler_inputs())
            .map(|i| {
                let q = c.garbler_input_mod(i);
                let (zero, _) = garbler.encode_wire(0, q);
                zero
            })
            .collect_vec()
    );

    let mut ev_inps = eval_inputs;
    ev_inps.extend(
        (ev_inps.len()..c.num_evaluator_inputs())
            .map(|i| {
                let q = c.evaluator_input_mod(i);
                let (zero, _) = garbler.encode_wire(0, q);
                zero
            })
            .collect_vec()
    );

    let outputs = c.eval(&mut garbler, &gb_inps, &ev_inps)?;

    c.process_outputs(&outputs, &mut garbler)?;

    let en = Encoder::new(gb_inps, ev_inps, garbler.get_deltas());

    let gc = GarbledCircuit::new(
        Rc::try_unwrap(channel.writer())
            .unwrap()
            .into_inner()
            .blocks,
    );

    Ok((en, gc))
}

////////////////////////////////////////////////////////////////////////////////
// Encoder

/// Encode inputs statically.
#[derive(Debug)]
#[cfg_attr(feature = "serde1", derive(serde::Serialize, serde::Deserialize))]
pub struct Encoder {
    garbler_inputs: Vec<Wire>,
    evaluator_inputs: Vec<Wire>,
    deltas: HashMap<u16, Wire>,
}

impl Encoder {
    /// Make a new `Encoder` from lists of garbler and evaluator inputs,
    /// alongside a map of moduli-to-wire-offsets.
    pub fn new(
        garbler_inputs: Vec<Wire>,
        evaluator_inputs: Vec<Wire>,
        deltas: HashMap<u16, Wire>,
    ) -> Self {
        Encoder {
            garbler_inputs,
            evaluator_inputs,
            deltas,
        }
    }

    /// Get wire deltas
    pub fn get_deltas(&self) -> HashMap<u16, Wire> {
        self.deltas.clone()
    }

    /// Output the number of garbler inputs.
    pub fn num_garbler_inputs(&self) -> usize {
        self.garbler_inputs.len()
    }

    /// Output the number of evaluator inputs.
    pub fn num_evaluator_inputs(&self) -> usize {
        self.evaluator_inputs.len()
    }

    /// Encode a single garbler input into its associated wire-label.
    pub fn encode_garbler_input(&self, x: u16, id: usize) -> Wire {
        let X = &self.garbler_inputs[id];
        let q = X.modulus();
        X.plus(&self.deltas[&q].cmul(x))
    }

    /// Encode a single evaluator input into its associated wire-label.
    pub fn encode_evaluator_input(&self, x: u16, id: usize) -> Wire {
        let X = &self.evaluator_inputs[id];
        let q = X.modulus();
        X.plus(&self.deltas[&q].cmul(x))
    }

    /// Encode a slice of garbler inputs into their associated wire-labels.
    pub fn encode_garbler_inputs(&self, inputs: &[u16]) -> Vec<Wire> {
        debug_assert_eq!(inputs.len(), self.garbler_inputs.len());
        (0..inputs.len())
            .zip(inputs)
            .map(|(id, &x)| self.encode_garbler_input(x, id))
            .collect()
    }

    /// Encode a slice of evaluator inputs into their associated wire-labels.
    pub fn encode_evaluator_inputs(&self, inputs: &[u16]) -> Vec<Wire> {
        debug_assert_eq!(inputs.len(), self.evaluator_inputs.len());
        (0..inputs.len())
            .zip(inputs)
            .map(|(id, &x)| self.encode_evaluator_input(x, id))
            .collect()
    }
}

////////////////////////////////////////////////////////////////////////////////
// Reader and Writer impls for simple local structures to collect and release blocks

/// Implementation of the `Read` trait for use by the `Evaluator`.
#[derive(Debug)]
struct GarbledReader {
    blocks: Vec<Block>,
    index: usize,
}

impl GarbledReader {
    fn new(blocks: &[Block]) -> Self {
        Self {
            blocks: blocks.to_vec(),
            index: 0,
        }
    }
}

impl std::io::Read for GarbledReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        assert_eq!(buf.len() % 16, 0);
        for data in buf.chunks_mut(16) {
            let block: [u8; 16] = self.blocks[self.index].into();
            for (a, b) in data.iter_mut().zip(block.iter()) {
                *a = *b;
            }
            self.index += 1;
        }
        Ok(buf.len())
    }
}

/// Implementation of the `Write` trait for use by `Garbler`.
#[derive(Debug)]
pub struct GarbledWriter {
    blocks: Vec<Block>,
}

impl GarbledWriter {
    /// Make a new `GarbledWriter`.
    pub fn new(ngates: Option<usize>) -> Self {
        let blocks = if let Some(n) = ngates {
            Vec::with_capacity(2 * n)
        } else {
            Vec::new()
        };
        Self { blocks }
    }
}

impl std::io::Write for GarbledWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        for item in buf.chunks(16) {
            let bytes: [u8; 16] = match item.try_into() {
                Ok(bytes) => bytes,
                Err(_) => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "unable to map bytes to block",
                    ));
                }
            };
            self.blocks.push(Block::from(bytes));
        }
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
