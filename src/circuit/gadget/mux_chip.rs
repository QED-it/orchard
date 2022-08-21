use halo2_proofs::circuit::Value;
use halo2_proofs::{
    circuit::{AssignedCell, Chip, Layouter},
    plonk::{self, Advice, Column, ConstraintSystem, Constraints, Expression, Selector},
    poly::Rotation,
};
use pasta_curves::arithmetic::CurveAffine;
use pasta_curves::pallas;

#[derive(Clone, Debug)]
pub(in crate::circuit) struct MuxConfig {
    q_mux: Selector,
    switch: Column<Advice>,
    left: Column<Advice>,
    right: Column<Advice>,
    out: Column<Advice>,
}

/// A chip implementing a multiplexer on a single row.
///
/// out = if (switch == 0) { left } else { right }
///
/// Switch must be constrained to {0, 1} separately.
pub(in crate::circuit) struct MuxChip {
    config: MuxConfig,
}

impl Chip<pallas::Base> for MuxChip {
    type Config = MuxConfig;
    type Loaded = ();

    fn config(&self) -> &Self::Config {
        &self.config
    }

    fn loaded(&self) -> &Self::Loaded {
        &()
    }
}

impl MuxChip {
    pub(in crate::circuit) fn configure(
        meta: &mut ConstraintSystem<pallas::Base>,
        switch: Column<Advice>,
        left: Column<Advice>,
        right: Column<Advice>,
        out: Column<Advice>,
    ) -> MuxConfig {
        let q_mux = meta.selector();

        meta.create_gate("Field element multiplexer", |meta| {
            let q_mux = meta.query_selector(q_mux);
            let switch = meta.query_advice(switch, Rotation::cur());
            let left = meta.query_advice(left, Rotation::cur());
            let right = meta.query_advice(right, Rotation::cur());
            let out = meta.query_advice(out, Rotation::cur());

            let one = Expression::Constant(pallas::Base::one());
            let not_switch = one - switch.clone();
            let should_be_zero = not_switch * left + switch * right - out;

            Constraints::with_selector(q_mux, Some(should_be_zero))
        });

        MuxConfig {
            q_mux,
            switch,
            left,
            right,
            out,
        }
    }

    pub(in crate::circuit) fn construct(config: MuxConfig) -> Self {
        Self { config }
    }
}

pub trait MuxInstructions<C: CurveAffine> {
    fn mux(
        &self,
        layouter: impl Layouter<C::Base>,
        switch: &AssignedCell<C::Base, C::Base>,
        left: &AssignedCell<C::Base, C::Base>,
        right: &AssignedCell<C::Base, C::Base>,
    ) -> Result<AssignedCell<C::Base, C::Base>, plonk::Error>;
}

impl MuxInstructions<pallas::Affine> for MuxChip {
    fn mux(
        &self,
        mut layouter: impl Layouter<pallas::Base>,
        switch: &AssignedCell<pallas::Base, pallas::Base>,
        left: &AssignedCell<pallas::Base, pallas::Base>,
        right: &AssignedCell<pallas::Base, pallas::Base>,
    ) -> Result<AssignedCell<pallas::Base, pallas::Base>, plonk::Error> {
        layouter.assign_region(
            || "mux",
            |mut region| {
                // Enable the multiplexer gate.
                self.config.q_mux.enable(&mut region, 0)?;

                // Copy the inputs into the multiplexer row.
                switch.copy_advice(|| "copy switch", &mut region, self.config.switch, 0)?;
                left.copy_advice(|| "copy left", &mut region, self.config.left, 0)?;
                right.copy_advice(|| "copy right", &mut region, self.config.right, 0)?;

                // Assign the output value into the multiplexer row.
                let out_val = compute_mux(switch.value(), left.value(), right.value());

                region.assign_advice(|| "out", self.config.out, 0, || out_val)
            },
        )
    }
}

fn compute_mux(
    switch: Value<&pallas::Base>,
    left: Value<&pallas::Base>,
    right: Value<&pallas::Base>,
) -> Value<pallas::Base> {
    let one = Value::known(pallas::Base::one());
    let not_switch = one - switch;
    not_switch * left + switch * right
}
